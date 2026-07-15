FROM node:22-bookworm AS dashboard
WORKDIR /app/web/dashboard
COPY web/dashboard/package.json web/dashboard/pnpm-lock.yaml web/dashboard/pnpm-workspace.yaml ./
RUN corepack enable && pnpm install --frozen-lockfile
COPY web/dashboard ./
RUN pnpm build

FROM rust:1-bookworm AS builder
WORKDIR /app
COPY Cargo.toml ./
COPY crates ./crates
RUN cargo build --release -p sknr

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/sknr /usr/local/bin/sknr
COPY --from=dashboard /app/web/dashboard/out /app/web/dashboard/out
COPY scripts/github-action-entrypoint.sh /usr/local/bin/sknr-action
RUN chmod +x /usr/local/bin/sknr-action
ENTRYPOINT ["sknr"]
