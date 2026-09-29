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
use weaveauth_plugin_sdk::{Plugin, PluginRequest, PluginResponse, Request, Response, Status, serve};

const DATABASE_URL: &str = "DATABASE_URL";

struct PgProbe {
    pool: Pool,
}

#[weaveauth_plugin_sdk::async_trait]
impl Plugin for PgProbe {
    async fn invoke(&self, request: Request<PluginRequest>) -> Result<Response<PluginResponse>, Status> {
        let request = request.into_inner();
        if request.hook != "registration" {
            // This plugin is only ever wired into `extra_data_handler` -- see
            // the proto's own comment on why unimplemented is the correct
            // answer for a hook a plugin isn't wired into.
            return Err(Status::unimplemented(format!("pg-probe-plugin does not handle hook {:?}", request.hook)));
        }

        let company = match request.data.as_ref().and_then(|data| data.fields.get("company")) {
            Some(prost_types::Value { kind: Some(prost_types::value::Kind::StringValue(company)) }) => company.clone(),
            _ => String::new(),
        };

        let client = self.pool.get().await.map_err(|error| Status::unavailable(error.to_string()))?;
        client
            .execute(
                "insert into profile (user_id, email, company) values ($1, $2, $3)",
                &[&request.user_id, &request.email, &company],
            )
            .await
            .map_err(|error| Status::unavailable(error.to_string()))?;

        Ok(Response::new(PluginResponse { data: None }))
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
