# Stage 1: Build all binaries. Trixie, to match the runtime's glibc.
FROM rust:1.98-slim-trixie AS builder
# openssl-sys (reqwest's native-tls, via openidconnect) needs the headers and
# pkg-config to build; the distroless runtime ships libssl itself. libcap2-bin
# is for setcap below.
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev libcap2-bin \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN cargo build --release -p weaveauth -p weaveauth-bff -p weaveauth-login -p weaveauth-launcher

# Each plugin runs as its own user, which takes CAP_SETUID/CAP_SETGID. Only the
# tiny weaveauth-plugin-exec helper gets them, as file caps: backend holds none,
# so a deployment without plugins needs no capabilities at all, and a
# compromised backend, bff or login (all weaveauth) can reach a plugin's user
# through it but never root (the helper refuses uid/gid 0).
# root:weaveauth 0710, so only group 1000 can run it -- never a plugin.
# setcap last: chown clears file caps.
RUN chown 0:1000 target/release/weaveauth-plugin-exec \
    && chmod 0710 target/release/weaveauth-plugin-exec \
    && setcap cap_setuid,cap_setgid+ep target/release/weaveauth-plugin-exec

# distroless has no useradd. weaveauth (1000) runs the services; each plugin
# hook defaults to a user of its own. The kernel needs no entry to switch to
# a uid -- these only give the defaults names in `ps`/`docker top`.
RUN printf '%s\n' \
        'root:x:0:0:root:/root:/sbin/nologin' \
        'nobody:x:65534:65534:nobody:/nonexistent:/sbin/nologin' \
        'weaveauth:x:1000:1000:weaveauth:/nonexistent:/sbin/nologin' \
        'wa-registration:x:1001:1001:registration plugin:/nonexistent:/sbin/nologin' \
        'wa-login-claims:x:1002:1002:login claims plugin:/nonexistent:/sbin/nologin' \
        'wa-email:x:1003:1003:email plugin:/nonexistent:/sbin/nologin' > /etc/passwd.runtime \
    && printf '%s\n' \
        'root:x:0:' \
        'nogroup:x:65534:' \
        'weaveauth:x:1000:' \
        'wa-registration:x:1001:' \
        'wa-login-claims:x:1002:' \
        'wa-email:x:1003:' > /etc/group.runtime
RUN mkdir /empty

# Stage 2: Runtime. No shell and no package manager; backend execs plugin
# binaries directly, so none is needed.
FROM gcr.io/distroless/cc-debian13 AS runtime
COPY --from=builder /etc/passwd.runtime /etc/passwd
COPY --from=builder /etc/group.runtime /etc/group
COPY --from=builder /app/target/release/weaveauth /usr/local/bin/weaveauth
COPY --from=builder /app/target/release/weaveauth-bff /usr/local/bin/weaveauth-bff
COPY --from=builder /app/target/release/weaveauth-login /usr/local/bin/weaveauth-login
COPY --from=builder /app/target/release/weaveauth-launcher /usr/local/bin/weaveauth-launcher
# No --chown/--chmod: that would risk the caps xattr. Owner, mode and caps
# carry over from the builder; plugin_privsep_flow.rs checks all three.
COPY --from=builder /app/target/release/weaveauth-plugin-exec /usr/local/bin/weaveauth-plugin-exec
COPY --from=builder /app/login/static /app/login/static
# Deployer-replaceable templates: pages/ (login, register, ...) and emails/. Both services
# read them from here (baked in at build time as /app/<crate>/../templates), so
# /app/backend must exist (empty) for the `..` to resolve.
COPY --from=builder /app/templates /app/templates
COPY --from=builder /empty /app/backend
ENV WA_SETUID_HELPER=/usr/local/bin/weaveauth-plugin-exec
USER weaveauth
EXPOSE 1983 8080 8081
ENTRYPOINT ["/usr/local/bin/weaveauth-launcher"]
