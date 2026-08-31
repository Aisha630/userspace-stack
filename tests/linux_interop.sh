#!/usr/bin/env bash
set -euo pipefail

connections="${CONNECTIONS:-512}"
transfer_mib="${TRANSFER_MIB:-32}"

mkdir -p /dev/net
if [[ ! -c /dev/net/tun ]]; then
  mknod /dev/net/tun c 10 200
fi

target/release/ustack --tap > /tmp/ustack.log 2>&1 &
stack_pid=$!
trap 'kill "$stack_pid" 2>/dev/null || true' EXIT

for _ in $(seq 1 50); do
  if ip link show tap0 >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
ip link show tap0 >/dev/null

ping -c 3 -W 1 10.0.0.2 >/dev/null
echo "PASS icmp_echo_linux_ping"

ip neigh show 10.0.0.2 dev tap0 | grep -Eq 'lladdr 02:00:00:00:00:02.*(REACHABLE|STALE|DELAY)'
echo "PASS arp_neighbor_resolution"

udp_reply="$(printf 'udp-echo' | nc -u -w 1 10.0.0.2 7)"
test "$udp_reply" = "udp-echo"
echo "PASS udp_echo_netcat"

tcp_reply="$(printf 'tcp-echo' | nc -q 1 -w 2 10.0.0.2 8080)"
test "$tcp_reply" = "tcp-echo"
echo "PASS tcp_handshake_echo_teardown_netcat"

python3 - "$connections" "$transfer_mib" <<'PY'
import socket
import sys
import time

connections = int(sys.argv[1])
target_bytes = int(sys.argv[2]) * 1024 * 1024
sockets = []

for _ in range(connections):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect(("10.0.0.2", 8080))
    sockets.append(sock)

payload = bytes([0xA5]) * (56 * 1024)
rounds = (target_bytes + len(payload) * connections - 1) // (len(payload) * connections)
transferred = 0
started = time.perf_counter()

for _ in range(rounds):
    for sock in sockets:
        sock.sendall(payload)
        received = bytearray()
        while len(received) < len(payload):
            chunk = sock.recv(len(payload) - len(received))
            if not chunk:
                raise RuntimeError("TCP connection closed before echo completed")
            received.extend(chunk)
        if received != payload:
            raise RuntimeError("TCP echo payload mismatch")
        transferred += len(payload)

elapsed = time.perf_counter() - started
for sock in sockets:
    sock.close()

mbps = transferred * 8 / elapsed / 1_000_000
print("PASS concurrent_tcp_echo")
print(f"connections={connections}")
print(f"payload_bytes={transferred}")
print(f"elapsed_seconds={elapsed:.6f}")
print(f"throughput_mbps={mbps:.2f}")
PY

kill "$stack_pid"
wait "$stack_pid" 2>/dev/null || true

target/release/ustack --tun --name tun0 --ip 10.2.0.2 --host-ip 10.2.0.1 > /tmp/ustack-tun.log 2>&1 &
stack_pid=$!
for _ in $(seq 1 50); do
  if ip link show tun0 >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
ip link show tun0 >/dev/null

ping -c 3 -W 1 10.2.0.2 >/dev/null
echo "PASS tun_icmp_echo_linux_ping"

tun_tcp_reply="$(printf 'tun-tcp-echo' | nc -q 1 -w 2 10.2.0.2 8080)"
test "$tun_tcp_reply" = "tun-tcp-echo"
echo "PASS tun_tcp_echo_netcat"

echo "linux_interop_tests=7"
