//! The whole stack: real Kratos, Hydra, Postgres and Mailpit in containers, configured from the
//! repo's `ory/` files, with hooks, bff and login running in this process. Containers reach the
//! host's services through `host.docker.internal`; the host reaches containers on mapped ports.

use super::browser::Browser;
use super::{edge, idp, stubs};
use anyhow::{Context, bail};
use secrecy::SecretString;
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use testcontainers::core::wait::ExitWaitStrategy;
use testcontainers::core::{CmdWaitFor, ExecCommand, Host, IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use tokio::net::TcpListener;

const KRATOS_IMAGE: (&str, &str) = ("oryd/kratos", "v26.2.0");
const HYDRA_IMAGE: (&str, &str) = ("oryd/hydra", "v26.2.0");

pub const BFF_CLIENT_ID: &str = "bff";
pub const BFF_CLIENT_SECRET: &str = "system-test-bff-client-secret";
pub const BFF_INTERNAL_API_KEY: &str = "system-test-bff-internal-key";
pub const HOOKS_API_KEY: &str = "5c1d0f4a9e7b43d2a86f0c3be91d7a15";
/// A destination on bff's allowlist; nothing listens there, the browser stops before it.
pub const REDIRECT_URI: &str = "http://app.localhost:9/done";

/// Ids and the network of everything this process started, for the exit hook.
static STARTED: Mutex<(Vec<String>, Vec<String>)> = Mutex::new((Vec::new(), Vec::new()));

#[derive(Clone, Copy, Default)]
pub struct Options {
    /// Load `session-on-registration.yml`: registering signs the user in without verifying first.
    pub session_on_registration: bool,
}

pub struct Stack {
    /// The login host as a browser sees it, with Hydra's `/oauth2/auth` and logout behind it.
    pub login_url: String,
    pub bff_url: String,
    /// Where hooks (and the tests) reach bff's internal listener.
    pub bff_internal_url: String,
    pub kratos_admin: String,
    pub hydra_admin: String,
    pub hydra_public: String,
    pub mail_api: String,
    pub stubs: Arc<stubs::Stubs>,
    pub http: reqwest::Client,
    postgres: ContainerAsync<GenericImage>,
    _containers: Vec<ContainerAsync<GenericImage>>,
}

struct Reserved {
    listener: TcpListener,
    port: u16,
}

async fn reserve(any_interface: bool) -> anyhow::Result<Reserved> {
    let addr = if any_interface {
        "0.0.0.0:0"
    } else {
        "127.0.0.1:0"
    };
    let listener = TcpListener::bind(addr).await?;
    let port = listener.local_addr()?.port();
    Ok(Reserved { listener, port })
}

fn serve(reserved: Reserved, router: axum::Router) {
    tokio::spawn(async move {
        let _ = axum::serve(
            reserved.listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
}

fn ory_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../ory")
}

/// Everything under `dir` that `skip` doesn't name, as (path relative to `dir`, absolute path).
fn files_under(dir: &Path, skip: &[&str]) -> Vec<(String, PathBuf)> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()))
            .flatten()
            .collect();
        entries.sort_by_key(|e| e.path());
        for entry in entries {
            let path = entry.path();
            if path.is_dir() {
                walk(root, &path, out);
            } else if let Ok(rel) = path.strip_prefix(root) {
                out.push((rel.to_string_lossy().into_owned(), path));
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.retain(|(rel, _)| !skip.contains(&rel.as_str()));
    out
}

/// What differs between `local-prod` and this stack, applied to the repo's config files.
struct Rendering {
    pairs: Vec<(String, String)>,
}

impl Rendering {
    fn apply(&self, text: &str) -> String {
        self.pairs
            .iter()
            .fold(text.to_string(), |text, (from, to)| text.replace(from, to))
    }

    fn file(&self, rel: &str) -> anyhow::Result<Vec<u8>> {
        let path = ory_dir().join(rel);
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        Ok(self.apply(&text).into_bytes())
    }
}

/// An entrypoint script of `ory/` with `--dev` added after `serve_command`.
fn dev_script(rel: &str, serve_command: &str) -> anyhow::Result<Vec<u8>> {
    let path = ory_dir().join(rel);
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    anyhow::ensure!(
        text.contains(serve_command),
        "{rel} no longer runs `{serve_command}`"
    );
    Ok(text
        .replace(serve_command, &format!("{serve_command} --dev"))
        .into_bytes())
}

fn record(container: &ContainerAsync<GenericImage>) {
    if let Ok(mut started) = STARTED.lock() {
        started.0.push(container.id().to_string());
    }
}

async fn start(
    request: testcontainers::ContainerRequest<GenericImage>,
) -> anyhow::Result<ContainerAsync<GenericImage>> {
    let container = request.start().await?;
    record(&container);
    Ok(container)
}

/// Removes the containers and the network this process started. Runs when the process exits.
pub fn cleanup() {
    let Ok(started) = STARTED.lock() else { return };
    let (containers, networks) = &*started;
    if !containers.is_empty() {
        let _ = std::process::Command::new("docker")
            .args(["rm", "-f", "-v"])
            .args(containers)
            .output();
    }
    for network in networks {
        let _ = std::process::Command::new("docker")
            .args(["network", "rm", network])
            .output();
    }
}

async fn wait_until_ready(
    url: String,
    what: &str,
    container: &ContainerAsync<GenericImage>,
) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    for _ in 0..120 {
        if client
            .get(&url)
            .send()
            .await
            .is_ok_and(|r| r.status().is_success())
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let stderr = container.stderr_to_vec().await.unwrap_or_default();
    let stdout = container.stdout_to_vec().await.unwrap_or_default();
    bail!(
        "{what} did not become ready at {url}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    )
}

impl Stack {
    pub async fn start(options: Options) -> anyhow::Result<Self> {
        // The in-process services log through `tracing`; RUST_LOG picks the level (default info).
        weaveauth_hooks::cli::init_tracing();
        let began = std::time::Instant::now();
        let note = |what: &str| eprintln!("[stack {:>5.1}s] {what}", began.elapsed().as_secs_f32());
        let run = &uuid::Uuid::new_v4().simple().to_string()[..8];
        let network = format!("wa-st-{run}-net");
        let (pg_name, kratos_name, hydra_name, mail_name) = (
            format!("wa-st-{run}-pg"),
            format!("wa-st-{run}-kratos"),
            format!("wa-st-{run}-hydra"),
            format!("wa-st-{run}-mail"),
        );
        STARTED.lock().expect("started").1.push(network.clone());

        // Ports first: the Ory configs name the host's services.
        let hooks_port = reserve(true).await?;
        let idp_port = reserve(true).await?;
        let bff_internal_port = reserve(true).await?;
        let login_port = reserve(false).await?;
        let bff_port = reserve(false).await?;
        let stubs_port = reserve(false).await?;

        let login_url = format!("http://login.localhost:{}", login_port.port);
        let bff_url = format!("http://bff.localhost:{}", bff_port.port);
        let idp_base = format!("http://host.docker.internal:{}", idp_port.port);
        let stubs_url = format!("http://127.0.0.1:{}", stubs_port.port);
        let bff_internal_for_hydra =
            format!("http://host.docker.internal:{}", bff_internal_port.port);

        let rendering = Rendering {
            pairs: vec![
                ("https://login.localhost:8443".into(), login_url.clone()),
                ("https://bff.localhost:8443".into(), bff_url.clone()),
                (
                    "http://weaveauth:1983".into(),
                    format!("http://host.docker.internal:{}", hooks_port.port),
                ),
                (
                    "http://hydra-admin:4445".into(),
                    format!("http://{hydra_name}:4445"),
                ),
                (
                    "http://kratos:4434".into(),
                    format!("http://{kratos_name}:4434"),
                ),
                // The test host may have no route to Pwned Passwords.
                (
                    "ignore_network_errors: false".into(),
                    "ignore_network_errors: true".into(),
                ),
                (
                    "smtp://mail:1025/".into(),
                    format!("smtp://{mail_name}:1025/?disable_starttls=true"),
                ),
            ],
        };

        let db_password = "system-test-db-password";
        let kratos_dsn =
            format!("postgres://kratos:{db_password}@{pg_name}:5432/kratos?sslmode=disable");
        let hydra_dsn =
            format!("postgres://hydra:{db_password}@{pg_name}:5432/hydra?sslmode=disable");

        note("starting postgres and mailpit");
        let postgres = start(
            GenericImage::new("postgres", "18-alpine")
                .with_network(&network)
                .with_container_name(&pg_name)
                .with_env_var("POSTGRES_PASSWORD", "system-test-postgres")
                .with_env_var("KRATOS_DB_PASSWORD", db_password)
                .with_env_var("HYDRA_DB_PASSWORD", db_password)
                .with_copy_to(
                    "/docker-entrypoint-initdb.d/init-dbs.sh",
                    Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("../local-prod/postgres/init-dbs.sh"),
                ),
        );
        let mail = start(
            GenericImage::new("axllent/mailpit", "v1.31")
                .with_exposed_port(8025.tcp())
                .with_network(&network)
                .with_container_name(&mail_name),
        );
        let (postgres, mail) = tokio::try_join!(postgres, mail)?;
        let mail_api = format!(
            "http://127.0.0.1:{}",
            mail.get_host_port_ipv4(8025.tcp()).await?
        );

        // The init scripts run on a socket-only server first; TCP answering means the real one is up.
        for _ in 0..120 {
            let ready = postgres
                .exec(
                    ExecCommand::new(["pg_isready", "-h", "127.0.0.1", "-U", "postgres"])
                        .with_cmd_ready_condition(CmdWaitFor::exit()),
                )
                .await?
                .exit_code()
                .await?;
            if ready == Some(0) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        note("postgres ready; migrating");
        let migrate = |image: (&str, &str), cmd: &[&str], dsn: &str, name: &str| {
            start(
                GenericImage::new(image.0, image.1)
                    .with_network(&network)
                    .with_container_name(name)
                    .with_env_var("DSN", dsn)
                    .with_cmd(cmd.iter().copied())
                    .with_ready_conditions(vec![WaitFor::exit(
                        ExitWaitStrategy::new().with_exit_code(0),
                    )]),
            )
        };
        let (kratos_migrate, hydra_migrate) = tokio::try_join!(
            migrate(
                KRATOS_IMAGE,
                &["migrate", "sql", "-e", "--yes"],
                &kratos_dsn,
                &format!("{kratos_name}-migrate")
            ),
            migrate(
                HYDRA_IMAGE,
                &["migrate", "sql", "up", "-e", "--yes"],
                &hydra_dsn,
                &format!("{hydra_name}-migrate")
            ),
        )?;

        note("migrated; starting kratos and hydra");
        // Both services refuse http URLs unless started with --dev, which the http test hosts need.
        let skip = [
            "kratos.yml",
            "session-on-registration.yml",
            "oidc-google.yml",
            "oidc-google-phone.yml",
            "start.sh",
        ];
        let mut kratos = GenericImage::new(KRATOS_IMAGE.0, KRATOS_IMAGE.1)
            .with_entrypoint("/bin/sh")
            .with_exposed_port(4433.tcp())
            .with_exposed_port(4434.tcp())
            .with_network(&network)
            .with_container_name(&kratos_name)
            .with_cmd(["/etc/kratos/start.sh"])
            .with_env_var("DSN", &kratos_dsn)
            .with_env_var("SECRETS_COOKIE", "system-test-kratos-cookie-secret!")
            .with_env_var("SECRETS_CIPHER", "system-test-kratos-cipher-secret")
            .with_env_var("WA_HOOKS_API_KEY", HOOKS_API_KEY)
            .with_env_var("KRATOS_CONFIG_EXTRA", "/etc/kratos/fake-idp.yml")
            .with_copy_to(
                "/etc/kratos/kratos.yml",
                rendering.file("kratos/kratos.yml")?,
            )
            .with_copy_to(
                "/etc/kratos/start.sh",
                dev_script("kratos/start.sh", "kratos serve")?,
            )
            .with_copy_to(
                "/etc/kratos/fake-idp.yml",
                idp::kratos_providers(&idp_base).into_bytes(),
            );
        if options.session_on_registration {
            kratos = kratos
                .with_env_var("KRATOS_SESSION_ON_REGISTRATION", "1")
                .with_copy_to(
                    "/etc/kratos/session-on-registration.yml",
                    rendering.file("kratos/session-on-registration.yml")?,
                );
        }
        for (rel, path) in files_under(&ory_dir().join("kratos"), &skip) {
            kratos = kratos.with_copy_to(format!("/etc/kratos/{rel}"), path);
        }

        // --- Hydra
        let mut hydra = GenericImage::new(HYDRA_IMAGE.0, HYDRA_IMAGE.1)
            .with_entrypoint("/bin/sh")
            .with_exposed_port(4444.tcp())
            .with_exposed_port(4445.tcp())
            .with_network(&network)
            .with_container_name(&hydra_name)
            .with_cmd(["/etc/hydra/start.sh"])
            .with_env_var("DSN", &hydra_dsn)
            .with_env_var("SECRETS_SYSTEM", "system-test-hydra-system-secret")
            .with_env_var("SECRETS_COOKIE", "system-test-hydra-cookie-secret")
            .with_env_var("WA_HOOKS_API_KEY", HOOKS_API_KEY)
            .with_copy_to("/etc/hydra/hydra.yml", rendering.file("hydra/hydra.yml")?)
            .with_copy_to(
                "/etc/hydra/start.sh",
                dev_script("hydra/start.sh", "hydra serve all")?,
            );
        for (rel, path) in files_under(&ory_dir().join("hydra"), &["hydra.yml", "start.sh"]) {
            hydra = hydra.with_copy_to(format!("/etc/hydra/{rel}"), path);
        }
        let kratos = kratos.with_host("host.docker.internal", Host::HostGateway);
        let hydra = hydra.with_host("host.docker.internal", Host::HostGateway);
        let (kratos, hydra) = tokio::try_join!(start(kratos), start(hydra))?;
        for (name, container) in [("kratos", &kratos), ("hydra", &hydra)] {
            tokio::time::sleep(Duration::from_secs(2)).await;
            if !container.is_running().await? {
                bail!(
                    "{name} exited:\n{}{}",
                    String::from_utf8_lossy(&container.stdout_to_vec().await.unwrap_or_default()),
                    String::from_utf8_lossy(&container.stderr_to_vec().await.unwrap_or_default())
                );
            }
        }
        let kratos_public = format!(
            "http://127.0.0.1:{}",
            kratos.get_host_port_ipv4(4433.tcp()).await?
        );
        let kratos_admin = format!(
            "http://127.0.0.1:{}",
            kratos.get_host_port_ipv4(4434.tcp()).await?
        );
        let hydra_public = format!(
            "http://127.0.0.1:{}",
            hydra.get_host_port_ipv4(4444.tcp()).await?
        );
        let hydra_admin = format!(
            "http://127.0.0.1:{}",
            hydra.get_host_port_ipv4(4445.tcp()).await?
        );
        tokio::try_join!(
            wait_until_ready(format!("{kratos_public}/health/ready"), "kratos", &kratos),
            wait_until_ready(format!("{hydra_admin}/health/ready"), "hydra", &hydra),
            wait_until_ready(format!("{mail_api}/api/v1/info"), "mailpit", &mail),
        )?;

        note("kratos and hydra ready");
        // The shipped init script creates the bff client.
        let init = hydra
            .exec(
                ExecCommand::new(["sh", "/etc/hydra/init-bff-client.sh"])
                    .with_cmd_ready_condition(CmdWaitFor::exit())
                    .with_env_vars([
                        ("HYDRA_ADMIN_URL", "http://127.0.0.1:4445"),
                        ("BFF_CLIENT_SECRET", BFF_CLIENT_SECRET),
                        ("BFF_URL", bff_url.as_str()),
                        ("BFF_INTERNAL_URL", bff_internal_for_hydra.as_str()),
                        ("POST_LOGOUT_URI", &format!("{bff_url}/logged-out")),
                    ]),
            )
            .await?;
        let init_code = init.exit_code().await?;
        if init_code != Some(0) {
            bail!("hydra client init exited with {init_code:?}");
        }

        // --- hooks, bff, login in this process
        note("bff client created; starting hooks, bff, login");
        let stubs = Arc::new(stubs::Stubs::default());
        let webhook = |path: &str| {
            Some(weaveauth_hooks::config::WebhookConfig {
                url: format!("{stubs_url}{path}"),
                timeout_secs: 10,
                bearer_token: None,
            })
        };
        let hooks = weaveauth_hooks::server::app(&weaveauth_hooks::config::Config {
            port: hooks_port.port,
            hooks_api_key: SecretString::from(HOOKS_API_KEY),
            kratos_admin_url: kratos_admin.clone(),
            hydra_admin_url: hydra_admin.clone(),
            bff_internal_url: format!("http://127.0.0.1:{}", bff_internal_port.port),
            bff_internal_api_key: SecretString::from(BFF_INTERNAL_API_KEY),
            registration_handler: webhook("/registration"),
            login_claims_handler: webhook("/claims"),
            require_verified_email: !options.session_on_registration,
            ..Default::default()
        })?;
        let (bff_public, bff_internal) =
            weaveauth_bff::server::apps(weaveauth_bff::config::Config {
                port: bff_port.port,
                internal_port: bff_internal_port.port,
                bff_url: bff_url.clone(),
                hydra_public_url: login_url.clone(),
                hydra_internal_url: hydra_public.clone(),
                bff_client_id: BFF_CLIENT_ID.into(),
                bff_client_secret: SecretString::from(BFF_CLIENT_SECRET),
                redirect_uri_allowlist: vec![REDIRECT_URI.into()],
                default_redirect_uri: Some(REDIRECT_URI.into()),
                internal_api_key: SecretString::from(BFF_INTERNAL_API_KEY),
                routes: vec![weaveauth_bff::config::RouteConfig {
                    path_prefix: "/downstream".into(),
                    upstream_url: format!("{stubs_url}/upstream"),
                }],
                rate_limit_max_attempts: 1000,
                rate_limit_proxy_max_attempts: 10_000,
                ..Default::default()
            })?;
        let login = weaveauth_login::app(weaveauth_login::Config {
            port: login_port.port,
            bff_url: bff_url.clone(),
            own_origin: login_url.clone(),
            default_redirect_uri: Some(REDIRECT_URI.into()),
            kratos_public_url: kratos_public.clone(),
            hydra_admin_url: hydra_admin.clone(),
            bff_client_id: BFF_CLIENT_ID.into(),
            rate_limit_max_attempts: 1000,
            rate_limit_proxy_max_attempts: 10_000,
            trusted_proxies: Vec::new(),
            ..Default::default()
        })?;
        let bff_internal_url = format!("http://127.0.0.1:{}", bff_internal_port.port);
        serve(hooks_port, hooks);
        serve(bff_port, bff_public);
        serve(bff_internal_port, bff_internal);
        serve(login_port, edge::router(login, &hydra_public));
        serve(idp_port, idp::router(&idp_base));
        serve(stubs_port, stubs::router(stubs.clone()));

        note("stack up");
        Ok(Self {
            login_url,
            bff_url,
            bff_internal_url,
            kratos_admin,
            hydra_admin,
            hydra_public,
            mail_api,
            stubs,
            // No pooling: a pooled connection's task belongs to the runtime of the test that opened it.
            http: reqwest::Client::builder()
                .pool_max_idle_per_host(0)
                .build()?,
            postgres,
            _containers: vec![mail, kratos_migrate, hydra_migrate, kratos, hydra],
        })
    }

    /// Runs SQL against the Kratos database, for state no API can set up (a passkey, say).
    pub async fn kratos_sql(&self, statement: &str) -> String {
        let mut result = self
            .postgres
            .exec(
                ExecCommand::new([
                    "psql",
                    "-U",
                    "postgres",
                    "-d",
                    "kratos",
                    "-v",
                    "ON_ERROR_STOP=1",
                    "-At",
                    "-c",
                    statement,
                ])
                .with_cmd_ready_condition(CmdWaitFor::exit()),
            )
            .await
            .expect("psql");
        let out =
            String::from_utf8_lossy(&result.stdout_to_vec().await.unwrap_or_default()).into_owned();
        let err =
            String::from_utf8_lossy(&result.stderr_to_vec().await.unwrap_or_default()).into_owned();
        assert_eq!(
            result.exit_code().await.expect("exit code"),
            Some(0),
            "psql: {err}"
        );
        out
    }

    /// Gives an identity a credential of `kind` (`passkey`, `totp`, ...) that the admin API
    /// cannot create, by inserting the row Kratos would have written.
    pub async fn add_credential(&self, identity_id: &str, kind: &str, config: &Value) {
        let config = config.to_string().replace('\'', "''");
        self.kratos_sql(&format!(
            "INSERT INTO identity_credentials \
               (id, config, identity_credential_type_id, identity_id, nid, version, created_at, updated_at) \
             SELECT gen_random_uuid(), '{config}'::jsonb, t.id, i.id, i.nid, 0, now(), now() \
             FROM identity_credential_types t, identities i \
             WHERE t.name = '{kind}' AND i.id = '{identity_id}'"
        ))
        .await;
    }

    pub fn browser(&self) -> Browser {
        Browser::new()
    }

    /// A Kratos admin call; the body is JSON, the answer is the status and the JSON (or null).
    pub async fn kratos(&self, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
        self.admin(&self.kratos_admin, method, path, body).await
    }

    pub async fn hydra(&self, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
        self.admin(&self.hydra_admin, method, path, body).await
    }

    async fn admin(
        &self,
        base: &str,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> (u16, Value) {
        let mut request = self.http.request(
            reqwest::Method::from_bytes(method.as_bytes()).expect("method"),
            format!("{base}{path}"),
        );
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.expect("admin request");
        let status = response.status().as_u16();
        let text = response.text().await.unwrap_or_default();
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    /// The Kratos identity with this email.
    pub async fn identity(&self, email: &str) -> Value {
        let (_, found) = self
            .kratos("GET", &format!("/admin/identities?credentials_identifier={email}&include_credential=password&include_credential=oidc&include_credential=webauthn"), None)
            .await;
        found
            .as_array()
            .and_then(|all| all.first().cloned())
            .unwrap_or_else(|| panic!("no identity for {email}"))
    }

    pub async fn identity_id(&self, email: &str) -> String {
        self.identity(email).await["id"]
            .as_str()
            .expect("identity id")
            .to_string()
    }

    /// Creates an identity through the admin API, with the given credentials.
    pub async fn create_identity(&self, email: &str, verified: bool, credentials: Value) -> String {
        let mut identity = json!({
            "schema_id": "default",
            "traits": {
                "email": email,
                "first_name": "Test",
                "last_name": "User",
                "phone_number": "+46701234567",
            },
            "state": "active",
            "credentials": credentials,
        });
        if verified {
            identity["verifiable_addresses"] = json!([
                {"value": email, "via": "email", "verified": true, "status": "completed"}
            ]);
        }
        let (status, created) = self
            .kratos("POST", "/admin/identities", Some(identity))
            .await;
        assert_eq!(status, 201, "creating {email}: {created}");
        created["id"].as_str().expect("identity id").to_string()
    }
}
