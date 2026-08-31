use std::time::Instant;
use userspace_stack::{Config, Stack, ipv4, tcp};

#[derive(Clone, Copy)]
struct Client {
    ip: [u8; 4],
    port: u16,
    sequence: u32,
    server_sequence: u32,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let connections = arg_value(&args, "--connections").unwrap_or(256);
    let target_mib = arg_value(&args, "--mib").unwrap_or(64);
    assert!((1..=20_000).contains(&connections));

    let local_ip = [10, 0, 0, 2];
    let mut stack = Stack::new(Config {
        local_ip,
        ..Config::default()
    });
    let now = Instant::now();
    let mut clients = Vec::with_capacity(connections);

    for i in 0..connections {
        let mut client = Client {
            ip: [
                10,
                1 + ((i / 65_000) % 250) as u8,
                ((i / 250) % 250) as u8,
                (i % 250 + 1) as u8,
            ],
            port: 10_000 + i as u16,
            sequence: 1_000_000 + i as u32 * 10_000,
            server_sequence: 0,
        };
        let syn = tcp::serialize(
            client.ip,
            local_ip,
            client.port,
            8080,
            client.sequence,
            0,
            tcp::SYN,
            65_535,
            &[],
        );
        let response = exchange(&mut stack, client.ip, local_ip, syn, now);
        let syn_ack = parse_tcp(local_ip, client.ip, &response);
        assert_eq!(syn_ack.flags & (tcp::SYN | tcp::ACK), tcp::SYN | tcp::ACK);
        client.sequence = client.sequence.wrapping_add(1);
        client.server_sequence = syn_ack.sequence.wrapping_add(1);
        let ack = tcp::serialize(
            client.ip,
            local_ip,
            client.port,
            8080,
            client.sequence,
            client.server_sequence,
            tcp::ACK,
            65_535,
            &[],
        );
        assert!(send(&mut stack, client.ip, local_ip, ack, now).is_empty());
        clients.push(client);
    }

    let payload = vec![0xa5; 1400];
    let target_bytes = target_mib * 1024 * 1024;
    let rounds = target_bytes.div_ceil(payload.len() * connections);
    let started = Instant::now();
    let mut transferred = 0usize;
    for _ in 0..rounds {
        for client in &mut clients {
            let data = tcp::serialize(
                client.ip,
                local_ip,
                client.port,
                8080,
                client.sequence,
                client.server_sequence,
                tcp::ACK | tcp::PSH,
                65_535,
                &payload,
            );
            let response = exchange(&mut stack, client.ip, local_ip, data, Instant::now());
            let echo = parse_tcp(local_ip, client.ip, &response);
            assert_eq!(echo.payload, payload);
            client.sequence = client.sequence.wrapping_add(payload.len() as u32);
            client.server_sequence = client.server_sequence.wrapping_add(payload.len() as u32);
            let ack = tcp::serialize(
                client.ip,
                local_ip,
                client.port,
                8080,
                client.sequence,
                client.server_sequence,
                tcp::ACK,
                65_535,
                &[],
            );
            assert!(send(&mut stack, client.ip, local_ip, ack, Instant::now()).is_empty());
            transferred += payload.len();
        }
    }
    let elapsed = started.elapsed();
    let mbps = transferred as f64 * 8.0 / elapsed.as_secs_f64() / 1_000_000.0;
    let segments_per_second = (rounds * connections) as f64 / elapsed.as_secs_f64();

    println!("connections={connections}");
    println!("payload_bytes={transferred}");
    println!("elapsed_seconds={:.6}", elapsed.as_secs_f64());
    println!("throughput_mbps={mbps:.2}");
    println!("echo_segments_per_second={segments_per_second:.0}");
    assert_eq!(stack.connection_count(), connections);
}

fn arg_value(args: &[String], name: &str) -> Option<usize> {
    args.iter()
        .position(|arg| arg == name)
        .and_then(|index| args.get(index + 1))
        .and_then(|value| value.parse().ok())
}

fn send(stack: &mut Stack, src: [u8; 4], dst: [u8; 4], tcp: Vec<u8>, now: Instant) -> Vec<Vec<u8>> {
    let ip = ipv4::serialize(src, dst, ipv4::PROTOCOL_TCP, 1, &tcp);
    stack.process_ipv4_packet(&ip, now)
}

fn exchange(stack: &mut Stack, src: [u8; 4], dst: [u8; 4], tcp: Vec<u8>, now: Instant) -> Vec<u8> {
    let mut responses = send(stack, src, dst, tcp, now);
    assert_eq!(responses.len(), 1);
    responses.pop().unwrap()
}

fn parse_tcp<'a>(src: [u8; 4], dst: [u8; 4], ip_bytes: &'a [u8]) -> tcp::Segment<'a> {
    let ip = ipv4::Packet::parse(ip_bytes).unwrap();
    assert_eq!(ip.src, src);
    assert_eq!(ip.dst, dst);
    tcp::Segment::parse(src, dst, ip.payload).unwrap()
}
