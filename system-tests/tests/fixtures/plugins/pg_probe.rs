//! A plugin that writes the registration into Postgres with an ordinary
//! connection pool -- the thing the process model exists for. It is a normal
//! binary, so `deadpool-postgres` works exactly as it would in any service.
//!
//! Built as a bin target of this package under the `docker` feature, and
//! driven by `plugin_postgres_flow`.

use std::str::FromStr;
use std::time::Duration;

use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod, Runtime};
use tokio_postgres::NoTls;
use weaveauth_plugin_sdk::{
    HandleRegistrationRequest, HandleRegistrationResponse, Plugin, Request, Response, Status, serve,
};

const DATABASE_URL: &str = "DATABASE_URL";

struct PgProbe {
    pool: Pool,
}

#[weaveauth_plugin_sdk::async_trait]
impl Plugin for PgProbe {
    async fn handle_registration(
        &self,
        request: Request<HandleRegistrationRequest>,
    ) -> Result<Response<HandleRegistrationResponse>, Status> {
        let registration = request.into_inner();
        let company = registration.fields.get("company").cloned().unwrap_or_default();

        let client = self.pool.get().await.map_err(|error| Status::unavailable(error.to_string()))?;
        client
            .execute(
                "insert into profile (user_id, email, company) values ($1, $2, $3)",
                &[&registration.user_id, &registration.email, &company],
            )
            .await
            .map_err(|error| Status::unavailable(error.to_string()))?;

        Ok(Response::new(HandleRegistrationResponse {}))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = std::env::var(DATABASE_URL)?;
    let config = tokio_postgres::Config::from_str(&url)?;

    // `Verified` rather than `Fast`: a pooled connection whose backend
    // Postgres terminated has to be replaced, and only a round trip proves
    // it is still there.
    let manager =
        Manager::from_config(config, NoTls, ManagerConfig { recycling_method: RecyclingMethod::Verified });
    let pool = Pool::builder(manager)
        .create_timeout(Some(Duration::from_secs(5)))
        .runtime(Runtime::Tokio1)
        .build()?;

    serve(PgProbe { pool }).await?;
    Ok(())
}
