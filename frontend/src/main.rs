use std::future::Future;

use topcoat::{
    Result,
    router::{page, Router, RouterBuilderDiscoverExt},
    view::{View, view},
};

#[tokio::main]
async fn main() {
    // topcoat's own default is 3000; pin the admin tool to 1984 unless PORT is set
    if std::env::var_os("PORT").is_none() {
        // SAFETY: single-threaded startup, before topcoat spawns its runtime
        unsafe { std::env::set_var("PORT", "1984") };
    }
    topcoat::start(Router::builder().discover().build())
        .await
        .unwrap();
}

#[page("/")]
async fn login() -> Result<impl View> {
    let oauth_url = std::env::var("OAUTH_LOGIN_URL")
        .unwrap_or_else(|_| "http://localhost:1983/oauth/login".to_string());

    Ok(view! {
        <!DOCTYPE html>
        <html>
            <head>
                <meta charset="utf-8">
                <title>"WeaveAuth"</title>
            </head>
            <body style="font-family: system-ui, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100svh; margin: 0; background-color: #0f172a; color: #f8fafc;">
                <main style="text-align: center;">
                    <h1>"WeaveAuth"</h1>
                    <p>"Sign in with your account to continue."</p>
                    <a href=(oauth_url) style="display: inline-block; padding: 0.6rem 1.4rem; border-radius: 0.5rem; background-color: #2563eb; color: #ffffff; text-decoration: none;">"Sign in"</a>
                </main>
            </body>
        </html>
    })
}