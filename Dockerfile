# Stage 1: Build all binaries
FROM rust:1.98-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p weaveauth -p weaveauth-bff -p weaveauth-login

# Stage 2: Runtime
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/weaveauth /usr/local/bin/weaveauth
COPY --from=builder /app/target/release/weaveauth-bff /usr/local/bin/weaveauth-bff
COPY --from=builder /app/target/release/weaveauth-login /usr/local/bin/weaveauth-login
COPY --from=builder /app/login/static /app/login/static
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
EXPOSE 1983 8080 8081
CMD ["entrypoint.sh"]
