//! A stand-in browser: follows redirects by hand, keeps cookies per host (not per port, like a
//! real browser), and resolves the test hostnames to loopback. Mirrors `ory/checks/browser.py`.

use reqwest::header::{HeaderMap, LOCATION, SET_COOKIE};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use url::Url;

/// Hostnames the browser resolves to 127.0.0.1 (the port stays the URL's).
const LOOPBACK_HOSTS: &[&str] = &["login.localhost", "bff.localhost", "host.docker.internal"];

const MAX_REDIRECTS: usize = 25;

/// What to do with a redirect.
#[derive(Clone, Copy)]
pub enum Follow<'a> {
    /// Return the redirecting response itself.
    No,
    /// Follow every redirect.
    All,
    /// Follow redirects, but return the redirecting response whose target starts with this.
    Until(&'a str),
}

pub struct Resp {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: String,
    /// The URL this response answered.
    pub url: Url,
}

impl Resp {
    pub fn location(&self) -> Option<&str> {
        self.headers.get(LOCATION).and_then(|v| v.to_str().ok())
    }

    pub fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|e| panic!("not JSON ({e}): {}", self.body))
    }

    pub fn query(&self, name: &str) -> Option<String> {
        self.url
            .query_pairs()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
    }

    /// The `Location` of a redirect, resolved against the request URL.
    pub fn redirect_target(&self) -> Option<Url> {
        self.url.join(self.location()?).ok()
    }
}

pub struct Browser {
    client: reqwest::Client,
    jar: Mutex<HashMap<String, BTreeMap<String, String>>>,
}

impl Default for Browser {
    fn default() -> Self {
        Self::new()
    }
}

impl Browser {
    pub fn new() -> Self {
        let loopback = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(60));
        for host in LOOPBACK_HOSTS {
            builder = builder.resolve(host, loopback);
        }
        Self {
            client: builder.build().expect("browser client"),
            jar: Mutex::default(),
        }
    }

    pub fn cookie(&self, url: &str, name: &str) -> Option<String> {
        let host = Url::parse(url).ok()?.host_str()?.to_string();
        self.jar.lock().ok()?.get(&host)?.get(name).cloned()
    }

    pub async fn get(&self, url: &str, follow: Follow<'_>) -> Resp {
        self.send("GET", url, Body::None, &[], follow).await
    }

    /// A `GET` asking for JSON, as Kratos' browser API clients do.
    pub async fn get_json(&self, url: &str) -> Resp {
        self.send(
            "GET",
            url,
            Body::None,
            &[("accept", "application/json")],
            Follow::No,
        )
        .await
    }

    pub async fn post_form(
        &self,
        url: &str,
        form: &[(String, String)],
        headers: &[(&str, &str)],
        follow: Follow<'_>,
    ) -> Resp {
        self.send("POST", url, Body::Form(form), headers, follow)
            .await
    }

    pub async fn send(
        &self,
        method: &str,
        url: &str,
        body: Body<'_>,
        headers: &[(&str, &str)],
        follow: Follow<'_>,
    ) -> Resp {
        let mut url = Url::parse(url).unwrap_or_else(|e| panic!("bad URL {url}: {e}"));
        let mut method = method.to_string();
        let mut body = Some(body);
        for _ in 0..MAX_REDIRECTS {
            let resp = self
                .once(&method, &url, body.take().unwrap_or(Body::None), headers)
                .await;
            let redirect = matches!(resp.status, 301 | 302 | 303 | 307 | 308);
            let Some(target) = resp.redirect_target().filter(|_| redirect) else {
                return resp;
            };
            match follow {
                Follow::No => return resp,
                Follow::Until(prefix) if target.as_str().starts_with(prefix) => return resp,
                _ => {}
            }
            url = target;
            method = "GET".into();
        }
        panic!("too many redirects ending at {url}");
    }

    async fn once(
        &self,
        method: &str,
        url: &Url,
        body: Body<'_>,
        headers: &[(&str, &str)],
    ) -> Resp {
        let host = url.host_str().unwrap_or_default().to_string();
        let mut request = self.client.request(
            reqwest::Method::from_bytes(method.as_bytes()).expect("method"),
            url.clone(),
        );
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let cookies = self
            .jar
            .lock()
            .expect("jar")
            .get(&host)
            .map(|jar| {
                jar.iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join("; ")
            })
            .unwrap_or_default();
        if !cookies.is_empty() {
            request = request.header("cookie", cookies);
        }
        request = match body {
            Body::None => request,
            Body::Form(form) => request.form(form),
            Body::Json(json) => request.json(json),
        };
        let response = request
            .send()
            .await
            .unwrap_or_else(|e| panic!("{method} {url}: {e}"));
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let text = response.text().await.unwrap_or_default();
        self.store_cookies(&host, &headers);
        Resp {
            status,
            headers,
            body: text,
            url: url.clone(),
        }
    }

    fn store_cookies(&self, host: &str, headers: &HeaderMap) {
        let mut jar = self.jar.lock().expect("jar");
        let jar = jar.entry(host.to_string()).or_default();
        for value in headers.get_all(SET_COOKIE) {
            let Ok(value) = value.to_str() else { continue };
            let (pair, attributes) = value.split_once(';').unwrap_or((value, ""));
            let Some((name, val)) = pair.split_once('=') else {
                continue;
            };
            let attributes = attributes.to_ascii_lowercase();
            let expired = attributes.contains("max-age=0")
                || attributes.contains("expires=thu, 01 jan 1970")
                || val.is_empty();
            if expired {
                jar.remove(name.trim());
            } else {
                jar.insert(name.trim().to_string(), val.to_string());
            }
        }
    }
}

pub enum Body<'a> {
    None,
    Form(&'a [(String, String)]),
    Json(&'a Value),
}
