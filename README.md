# userspace-stack

A dependency-free userspace TCP/IP stack in Rust. The protocol engine supports
Ethernet II, ARP, IPv4, ICMP echo, UDP echo, and a passive-open TCP state
machine with checksums, retransmission timers, duplicate-segment handling, and
active connection teardown. It runs over Linux TUN (layer 3) or TAP (layer 2).

## Run on Linux

The runner requires root or `CAP_NET_ADMIN` because it creates and configures a
TUN/TAP interface. TAP is the default:

```sh
cargo run --release --bin ustack
ping 10.0.0.2
printf hello | nc -w 2 10.0.0.2 8080
printf hello | nc -u -w 1 10.0.0.2 7
```

Use `--tun` for raw IPv4 packets. Pass `--no-configure` when another process is
responsible for configuring the interface.

## Verify in Docker Desktop

```sh
docker build -t userspace-stack .
docker run --rm --privileged userspace-stack
```

The container runs the Rust test suite, then checks ARP with `ip neigh`, ICMP
with `ping`, UDP/TCP echo with `nc`, and concurrent TCP sockets with Python.
Override the workload size with `CONNECTIONS` and `TRANSFER_MIB`, for example:

```sh
docker run --rm --privileged \
  -e CONNECTIONS=1024 -e TRANSFER_MIB=128 userspace-stack
```

## Portable benchmark

```sh
cargo run --release --bin stack-bench -- --connections 1024 --mib 64
```

This benchmark bypasses the device boundary and measures the deterministic
protocol engine in memory. Use the Docker interoperability benchmark for an
end-to-end number through the Linux networking stack and TAP device.

See [BENCHMARKS.md](BENCHMARKS.md) for recorded results and methodology.
