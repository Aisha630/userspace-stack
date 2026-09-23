# Benchmark results

Recorded on August 30, 2026, on an Apple M4 Pro MacBook Pro with 24 GB RAM,
using Docker Desktop's Linux/arm64 VM (Docker Engine 28.3.2).

## Matched smoltcp comparison

Recorded on September 23, 2026, using five runs per direction, Rust 1.91, each
project's release profile, and the same Docker Desktop Linux/arm64 VM. The
custom stack transferred 954 MiB (1,000,341,504 bytes) per run; smoltcp v0.14.0
transferred 1,000,000,000 bytes per run. Throughput is normalized by the exact
payload byte count.

| Stack | Stack → Linux | Linux → stack |
| --- | ---: | ---: |
| userspace-stack | 9.136 Gbps | 7.157 Gbps |
| smoltcp v0.14.0 | 7.111 Gbps | 17.131 Gbps |

Values are five-run medians. Relative to the pre-optimization build from commit
`7a334f7` (7.523 Gbps outbound and 4.569 Gbps inbound), the optimized stack is
21.4% faster outbound and 56.6% faster inbound. It is 28.5% faster than smoltcp
on the outbound path; smoltcp remains faster inbound.

## Optimization baseline

The pre-optimization build at commit `7a334f7` produced five-run medians of
7.523 Gbps from the stack to Linux and 4.569 Gbps from Linux to the stack under
the same 954 MiB workload. The current results improve those paths by 21.4% and
56.6%, respectively.

Commands:

```sh
docker build -t userspace-stack:bench .
docker run --rm --privileged --entrypoint target/release/tap-bench \
  userspace-stack:bench --mib 954 reader
docker run --rm --privileged --entrypoint target/release/tap-bench \
  userspace-stack:bench --mib 954 writer
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
elapsed_seconds=11.330884
throughput_mbps=787.71
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

Together with the 23 Rust tests, the project has 30 automated
protocol and Linux interoperability checks.

## In-memory protocol engine

```text
connections=1024
payload_bytes=134758400
elapsed_seconds=0.103727
throughput_mbps=10393.32
echo_segments_per_second=927975
```

Command:

```sh
cargo run --release --bin stack-bench -- --connections 1024 --mib 128
```

This isolates the protocol engine and excludes kernel/device I/O. It is useful
for regression testing, but the end-to-end TAP result is the résumé metric.
