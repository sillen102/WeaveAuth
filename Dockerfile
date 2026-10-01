# Stage 1: Build all binaries. Trixie, to match the runtime's glibc.
FROM rust:1.98-slim-trixie AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p weaveauth -p weaveauth-bff -p weaveauth-login -p weaveauth-launcher

# Backend spawns each plugin as its own user, which needs CAP_SETUID/CAP_SETGID.
# Granted as file caps so backend itself never runs as root. That also makes it
# non-dumpable: not even a same-uid process can read its /proc/<pid>/environ.
RUN apt-get update && apt-get install -y --no-install-recommends libcap2-bin \
    && setcap cap_setuid,cap_setgid+ep target/release/weaveauth

# distroless has no useradd. weaveauth (1000) runs the services; each plugin
# hook defaults to a user of its own. The kernel needs no entry to switch to
# a uid -- these only give the defaults names in `ps`/`docker top`.
RUN printf '%s\n' \
        'root:x:0:0:root:/root:/sbin/nologin' \
        'nobody:x:65534:65534:nobody:/nonexistent:/sbin/nologin' \
        'weaveauth:x:1000:1000:weaveauth:/nonexistent:/sbin/nologin' \
        'wa-registration:x:1001:1001:registration plugin:/nonexistent:/sbin/nologin' \
        'wa-login-claims:x:1002:1002:login claims plugin:/nonexistent:/sbin/nologin' > /etc/passwd.runtime \
    && printf '%s\n' \
        'root:x:0:' \
        'nogroup:x:65534:' \
        'weaveauth:x:1000:' \
        'wa-registration:x:1001:' \
        'wa-login-claims:x:1002:' > /etc/group.runtime

# Stage 2: Runtime. No shell and no package manager; backend execs plugin
# binaries directly, so none is needed.
FROM gcr.io/distroless/cc-debian13 AS runtime
COPY --from=builder /etc/passwd.runtime /etc/passwd
COPY --from=builder /etc/group.runtime /etc/group
COPY --from=builder /app/target/release/weaveauth /usr/local/bin/weaveauth
COPY --from=builder /app/target/release/weaveauth-bff /usr/local/bin/weaveauth-bff
COPY --from=builder /app/target/release/weaveauth-login /usr/local/bin/weaveauth-login
COPY --from=builder /app/target/release/weaveauth-launcher /usr/local/bin/weaveauth-launcher
COPY --from=builder /app/login/static /app/login/static
COPY --from=builder /app/login/templates /app/login/templates
USER weaveauth
EXPOSE 1983 8080 8081
ENTRYPOINT ["/usr/local/bin/weaveauth-launcher"]
