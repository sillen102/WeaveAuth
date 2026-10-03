//! Config loading shared by backend, bff and login: one precedence rule
//! (built-in defaults, then the YAML file, then the listed `WA_*` env vars)
//! and one place that decides which env vars exist.

use figment::Figment;
use figment::providers::{Env, Format, Serialized, Yaml};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::env;

/// How often the background tasks sweep expired entries out of the in-memory stores.
pub const EXPIRY_SWEEP_INTERVAL_SECS: u64 = 60;

/// A deployment's posture. Picks the defaults of settings that differ between
/// a laptop and production; anything set explicitly wins.
#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    Dev,
    #[default]
    Prod,
}

/// `(env var, config key)` pairs: the only env vars a service reads.
pub type EnvTable<'a> = &'a [(&'a str, &'a str)];

/// Loads `.env` from the working directory or a parent. A missing one is
/// normal; a malformed one would otherwise be dropped silently.
pub fn load_dotenv() -> anyhow::Result<()> {
    if let Err(error) = dotenvy::dotenv()
        && !error.not_found()
    {
        anyhow::bail!("could not load .env: {error}");
    }
    Ok(())
}

/// What the deployer set, and nothing else: the YAML file at `WA_CONFIG_FILE`
/// (default `config.yaml`; only when `read_file`), then the env vars in
/// `scalars`, then those in `lists` (comma-separated, trimmed, empties
/// dropped). Keeping this apart from the defaults lets a service tell "unset"
/// (derive it) from "set to the default" -- see [`Figment::contains`].
pub fn user_settings(
    read_file: bool,
    scalars: EnvTable,
    lists: EnvTable,
) -> anyhow::Result<Figment> {
    let mut user = Figment::new();
    if read_file {
        let path = env::var("WA_CONFIG_FILE").unwrap_or_else(|_| "config.yaml".into());
        // Figment treats a file it can't open like a missing one. Missing is
        // fine (no overlay); present but unreadable is a deployment mistake
        // that would otherwise run on defaults, dropping every setting in it.
        if let Err(error) = std::fs::File::open(&path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            anyhow::bail!("could not read config file {path:?}: {error}");
        }
        user = user.merge(Yaml::file(path));
    }

    let scalars: Vec<(String, String)> = scalars
        .iter()
        .map(|(var, key)| (var.to_string(), key.to_string()))
        .collect();
    user = user.merge(Env::raw().filter_map(move |var| {
        scalars
            .iter()
            .find(|(name, _)| name == var.as_str())
            .map(|(_, key)| key.clone().into())
    }));

    for (var, key) in lists {
        if let Ok(raw) = env::var(var) {
            let items: Vec<String> = raw
                .split(',')
                .map(|item| item.trim().to_string())
                .filter(|item| !item.is_empty())
                .collect();
            user = user.merge(Serialized::default(key, items));
        }
    }
    Ok(user)
}

/// `defaults` with everything in `user` laid over it.
pub fn extract<T: Serialize + DeserializeOwned>(defaults: T, user: &Figment) -> anyhow::Result<T> {
    Ok(Figment::from(Serialized::defaults(defaults))
        .merge(user.clone())
        .extract()?)
}

/// The `profile` the deployer set (`WA_PROFILE` or `profile:` in the YAML),
/// [`Profile::Prod`] when none. An unknown name is an error: falling back to
/// a profile the deployer didn't ask for would hide the typo.
pub fn profile(user: &Figment) -> anyhow::Result<Profile> {
    if !user.contains("profile") {
        return Ok(Profile::default());
    }
    user.extract_inner("profile")
        .map_err(|error| anyhow::anyhow!("invalid profile (expected dev or prod): {error}"))
}

/// What a browser-facing URL has to be under [`Profile::Prod`].
#[derive(Debug, Clone, Copy)]
pub enum PublicUrl {
    /// An https URL with a host; a path prefix is fine (`bff_url`, which
    /// others append routes to).
    Base,
    /// An https origin: no path, query or fragment. Compared verbatim with a
    /// browser's `Origin` header (`login_public_url`), which never has them.
    Origin,
}

/// Refuses to start in [`Profile::Prod`] unless each of `urls` (`(env var,
/// value, kind)`) is the https URL its kind asks for. A browser-facing URL on
/// plain http turns the session cookie's `Secure` flag off and puts http links
/// in emails; this also catches one left at its localhost default or set empty.
pub fn require_https_in_prod(
    profile: Profile,
    urls: &[(&str, &str, PublicUrl)],
) -> anyhow::Result<()> {
    if profile != Profile::Prod {
        return Ok(());
    }
    for (var, value, kind) in urls {
        let Ok(url) = url::Url::parse(value) else {
            anyhow::bail!("{var} must be an https URL for the prod profile{DEV_HINT}");
        };
        if url.scheme() != "https" || url.host().is_none() {
            anyhow::bail!("{var} must be an https URL for the prod profile{DEV_HINT}");
        }
        if matches!(kind, PublicUrl::Origin)
            && (url.path() != "/" || url.query().is_some() || url.fragment().is_some())
        {
            anyhow::bail!(
                "{var} must be an origin (no path, query or fragment) for the prod profile{DEV_HINT}"
            );
        }
    }
    Ok(())
}

const DEV_HINT: &str = ". Set WA_PROFILE=dev for local development";

#[cfg(test)]
// figment::Jail::expect_with's closure signature is fixed by the crate.
#[allow(clippy::result_large_err)]
mod tests {
    use super::*;
    use figment::Jail;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Sample {
        port: u16,
        name: String,
        origins: Vec<String>,
    }

    fn sample() -> Sample {
        Sample {
            port: 1,
            name: "default".into(),
            origins: vec!["http://default".into()],
        }
    }

    const SCALARS: EnvTable = &[("WA_SAMPLE_PORT", "port")];
    const LISTS: EnvTable = &[("WA_SAMPLE_ORIGINS", "origins")];

    #[test]
    fn env_overrides_file_overrides_defaults() {
        Jail::expect_with(|jail| {
            jail.create_file("config.yaml", "port: 2\nname: from-file\n")?;
            jail.set_env("WA_SAMPLE_PORT", "3");

            let user = user_settings(true, SCALARS, LISTS).unwrap();
            let config = extract(sample(), &user).unwrap();

            assert_eq!(config.port, 3);
            assert_eq!(config.name, "from-file");
            assert_eq!(config.origins, vec!["http://default".to_string()]);
            Ok(())
        });
    }

    #[test]
    fn only_listed_env_vars_are_read() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_NAME", "sneaky");
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");

            let user = user_settings(true, SCALARS, LISTS).unwrap();

            assert!(!user.contains("name"));
            assert_eq!(extract(sample(), &user).unwrap(), sample());
            Ok(())
        });
    }

    #[test]
    fn list_vars_split_trim_and_drop_empties() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env("WA_SAMPLE_ORIGINS", "http://a , http://b,,");

            let user = user_settings(true, SCALARS, LISTS).unwrap();

            assert_eq!(
                extract(sample(), &user).unwrap().origins,
                vec!["http://a".to_string(), "http://b".to_string()]
            );
            Ok(())
        });
    }

    #[test]
    fn contains_tells_what_the_deployer_set_from_a_default() {
        Jail::expect_with(|jail| {
            jail.create_file("config.yaml", "name: from-file\n")?;

            let user = user_settings(true, SCALARS, LISTS).unwrap();

            assert!(user.contains("name"));
            assert!(!user.contains("port"));
            Ok(())
        });
    }

    #[test]
    fn the_file_is_skipped_when_not_asked_for() {
        Jail::expect_with(|jail| {
            jail.create_file("config.yaml", "name: from-file\n")?;

            let user = user_settings(false, SCALARS, LISTS).unwrap();

            assert!(!user.contains("name"));
            Ok(())
        });
    }

    // A path through a regular file can't be opened even by root, unlike a
    // `chmod 000` file.
    #[test]
    fn refuses_a_config_file_it_cannot_read() {
        Jail::expect_with(|jail| {
            jail.create_file("config.yaml", "port: 2\n")?;
            jail.set_env("WA_CONFIG_FILE", "config.yaml/nested.yaml");

            let error = user_settings(true, SCALARS, LISTS)
                .expect_err("an unreadable config must not fall back to defaults");

            assert!(error.to_string().contains("config.yaml/nested.yaml"));
            Ok(())
        });
    }

    #[test]
    fn profile_defaults_to_prod() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");

            let user = user_settings(true, &[("WA_PROFILE", "profile")], &[]).unwrap();

            assert_eq!(profile(&user).unwrap(), Profile::Prod);
            Ok(())
        });
    }

    #[test]
    fn profile_reads_dev_from_env() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env("WA_PROFILE", "dev");

            let user = user_settings(true, &[("WA_PROFILE", "profile")], &[]).unwrap();

            assert_eq!(profile(&user).unwrap(), Profile::Dev);
            Ok(())
        });
    }

    #[test]
    fn prod_refuses_a_url_that_is_not_https() {
        for value in ["http://bff.example.com", "", "https://", "bff.example.com"] {
            let error =
                require_https_in_prod(Profile::Prod, &[("WA_SAMPLE_URL", value, PublicUrl::Base)])
                    .expect_err(value);
            assert!(error.to_string().contains("WA_SAMPLE_URL"), "{error}");
        }
    }

    #[test]
    fn prod_refuses_an_origin_with_a_path_query_or_fragment() {
        for value in [
            "https://login.example.com/app",
            "https://login.example.com/?x=1",
            "https://login.example.com/#x",
        ] {
            let error = require_https_in_prod(
                Profile::Prod,
                &[("WA_SAMPLE_URL", value, PublicUrl::Origin)],
            )
            .expect_err(value);
            assert!(error.to_string().contains("WA_SAMPLE_URL"), "{error}");
        }
    }

    #[test]
    fn prod_accepts_an_https_origin_and_a_base_with_a_path() {
        assert!(
            require_https_in_prod(
                Profile::Prod,
                &[
                    (
                        "WA_SAMPLE_URL",
                        "https://login.example.com/",
                        PublicUrl::Origin
                    ),
                    ("WA_SAMPLE_URL", "https://example.com/auth", PublicUrl::Base),
                ]
            )
            .is_ok()
        );
    }

    #[test]
    fn dev_accepts_http() {
        assert!(
            require_https_in_prod(
                Profile::Dev,
                &[(
                    "WA_SAMPLE_URL",
                    "http://localhost:8080/x",
                    PublicUrl::Origin
                )]
            )
            .is_ok()
        );
    }

    #[test]
    fn an_unknown_profile_is_an_error() {
        Jail::expect_with(|jail| {
            jail.set_env("WA_CONFIG_FILE", "/nonexistent/path.yaml");
            jail.set_env("WA_PROFILE", "staging");

            let user = user_settings(true, &[("WA_PROFILE", "profile")], &[]).unwrap();

            assert!(profile(&user).is_err());
            Ok(())
        });
    }
}
