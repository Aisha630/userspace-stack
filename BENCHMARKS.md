# Benchmark results

Recorded on August 30, 2026, on an Apple M4 Pro MacBook Pro with 24 GB RAM,
using Docker Desktop's Linux/arm64 VM (Docker Engine 28.3.2).

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

Together with the 19 Rust protocol tests, the project has 26 automated
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
