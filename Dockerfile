# Stage 1: Build all binaries. Trixie, to match the runtime's glibc.
FROM rust:1.98-slim-trixie AS builder
# openssl-sys (reqwest's native-tls, via openidconnect) needs the headers and
# pkg-config to build; the distroless runtime ships libssl itself.
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN cargo build --locked --release -p weaveauth-hooks -p weaveauth-bff -p weaveauth-login -p weaveauth-launcher

# distroless has no useradd. The kernel needs no entry to run as a uid; this only
# gives it a name in `ps`/`docker top`.
RUN printf '%s\n' \
        'root:x:0:0:root:/root:/sbin/nologin' \
        'nobody:x:65534:65534:nobody:/nonexistent:/sbin/nologin' \
        'weaveauth:x:1000:1000:weaveauth:/nonexistent:/sbin/nologin' > /etc/passwd.runtime \
    && printf '%s\n' \
        'root:x:0:' \
        'nogroup:x:65534:' \
        'weaveauth:x:1000:' > /etc/group.runtime

# Stage 2: Runtime. No shell and no package manager.
FROM gcr.io/distroless/cc-debian13 AS runtime
COPY --from=builder /etc/passwd.runtime /etc/passwd
COPY --from=builder /etc/group.runtime /etc/group
COPY --from=builder /app/target/release/weaveauth-hooks /usr/local/bin/weaveauth-hooks
COPY --from=builder /app/target/release/weaveauth-bff /usr/local/bin/weaveauth-bff
COPY --from=builder /app/target/release/weaveauth-login /usr/local/bin/weaveauth-login
COPY --from=builder /app/target/release/weaveauth-launcher /usr/local/bin/weaveauth-launcher
# login bakes these paths in at build time (<crate>/static, <crate>/../templates/{pages,providers}),
# so they must sit at the same absolute paths they were built at.
COPY --from=builder /app/login/static /app/login/static
COPY --from=builder /app/templates /app/templates
USER 1000:1000
# Only bff and login are public. hooks (1983) and bff's internal listener (8082) stay on the internal network.
EXPOSE 8080 8081
ENTRYPOINT ["/usr/local/bin/weaveauth-launcher"]
