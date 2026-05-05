FROM rust:1.95.0-bookworm as builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY public ./public

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/rust-waf /usr/local/bin/rust-waf
COPY --from=builder /app/public /app/public

RUN mkdir -p /app/config /var/lib/rust-waf /etc/ssl/private /etc/ssl/certs

ENV WAF_MODE=active
ENV TARGET_URL=http://localhost:3030
ENV ADMIN_PORT=8081
ENV TLS_PRIVATE=/etc/ssl/private/waf.key
ENV TLS_PUBLIC=/etc/ssl/certs/waf.crt
ENV WAF_CONFIG_PATH=/app/config/config.json
ENV WAF_RULES_PATH=/app/config/rules.json
ENV WAF_SEC_POLICIES_PATH=/app/config/sec_policies.json
ENV WAF_DB_PATH=/var/lib/rust-waf/waf.db

EXPOSE 443 8081

ENTRYPOINT ["/usr/local/bin/rust-waf"]
