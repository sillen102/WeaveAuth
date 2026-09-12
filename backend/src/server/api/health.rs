pub(crate) use controller::health;

mod controller {
    pub(crate) async fn health() -> &'static str {
        "ok"
    }
}

#[cfg(test)]
mod tests {
    use super::health;

    #[tokio::test]
    async fn returns_ok() {
        assert_eq!(health().await, "ok");
    }
}
