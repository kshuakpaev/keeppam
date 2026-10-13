FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates crates
RUN cargo build --release -p keeppam-agentd

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/agentd /usr/local/bin/agentd
COPY downloads/ /usr/share/keeppam-agent/downloads/
ENV AGENTD_HTTP_ADDR=0.0.0.0:8090 \
    AGENTD_DATA_DIR=/var/lib/agentd \
    AGENTD_DOWNLOADS_DIR=/usr/share/keeppam-agent/downloads
VOLUME /var/lib/agentd
EXPOSE 8090
ENTRYPOINT ["agentd"]
