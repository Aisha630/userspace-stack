# Benchmark results

Recorded on August 30, 2026, on an Apple M4 Pro MacBook Pro with 24 GB RAM,
using Docker Desktop's Linux/arm64 VM (Docker Engine 28.3.2).

## Directional TAP throughput

Recorded on September 3, 2026, using the same machine and Docker environment.
Each direction transfers 1 GiB over one TCP connection, matching the structure
of smoltcp's `examples/benchmark.rs`.

```text
mode=reader
payload_bytes=1073741824
elapsed_seconds=1.130551
throughput: 7.598 Gbps

mode=writer
payload_bytes=1073741824
elapsed_seconds=1.850275
throughput: 4.643 Gbps
```

Commands:

```sh
docker build -t userspace-stack:bench .
docker run --rm --privileged --entrypoint target/release/tap-bench \
  userspace-stack:bench --mib 1024 reader
docker run --rm --privileged --entrypoint target/release/tap-bench \
  userspace-stack:bench --mib 1024 writer
```

In `reader` mode, the userspace stack generates TCP payloads and a Linux
`TcpStream` reads them. In `writer` mode, the Linux `TcpStream` writes payloads
and the userspace stack acknowledges and discards them. The timer starts after
the TCP connection is established and covers payload transfer only. These are
end-to-end, one-direction measurements through Linux TAP, unlike the portable
in-memory benchmark below.

## Linux TAP interoperability path

```text
connections=1024
payload_bytes=1115684864
elapsed_seconds=17.128354
throughput_mbps=521.09
linux_interop_tests=7
```

Command:

```sh
docker run --rm --privileged \
  -e CONNECTIONS=1024 -e TRANSFER_MIB=1024 userspace-stack:local
```

The measurement includes Linux TCP sockets, IPv4 and Ethernet framing, TAP
device I/O, the userspace TCP state machine, and echoed payload verification.
The same run verifies ARP with `ip neigh`, ICMP with `ping`, UDP/TCP with `nc`,
and separately verifies ICMP/TCP over TUN.

Together with the 21 Rust protocol tests, the project has 28 automated
protocol and Linux interoperability checks.

## In-memory protocol engine

```text
connections=1024
payload_bytes=134758400
elapsed_seconds=0.118729
throughput_mbps=9080.05
echo_segments_per_second=810719
```

Command:

```sh
cargo run --release --bin stack-bench -- --connections 1024 --mib 128
```

This isolates the protocol engine and excludes kernel/device I/O. It is useful
for regression testing, but the end-to-end TAP result is the résumé metric.
