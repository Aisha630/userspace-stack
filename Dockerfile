FROM rust:1.89-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 iputils-ping netcat-openbsd python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /stack
COPY . .
RUN cargo build --release --bins && cargo test --release --all-targets

CMD ["bash", "tests/linux_interop.sh"]

