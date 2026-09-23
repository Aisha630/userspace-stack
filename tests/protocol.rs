use std::time::{Duration, Instant};
use userspace_stack::{Config, Stack, StackEvent, arp, ethernet, icmp, ipv4, tcp, udp};

const LOCAL_IP: [u8; 4] = [10, 0, 0, 2];
const REMOTE_IP: [u8; 4] = [10, 0, 0, 1];
const LOCAL_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 2];
const REMOTE_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 1];

fn stack() -> Stack {
    Stack::new(Config::default())
}

fn ip_to_stack(stack: &mut Stack, protocol: u8, payload: &[u8], now: Instant) -> Vec<Vec<u8>> {
    let packet = ipv4::serialize(REMOTE_IP, LOCAL_IP, protocol, 9, payload);
    stack.process_ipv4_packet(&packet, now)
}

#[derive(Debug)]
struct TcpResponse {
    sequence: u32,
    acknowledgment: u32,
    flags: u16,
    payload: Vec<u8>,
}

fn parse_tcp_response(ip_bytes: &[u8]) -> TcpResponse {
    let ip = ipv4::Packet::parse(ip_bytes).unwrap();
    let segment = tcp::Segment::parse(LOCAL_IP, REMOTE_IP, ip.payload).unwrap();
    TcpResponse {
        sequence: segment.sequence,
        acknowledgment: segment.acknowledgment,
        flags: segment.flags,
        payload: segment.payload.to_vec(),
    }
}

fn tcp_send(
    stack: &mut Stack,
    port: u16,
    seq: u32,
    ack: u32,
    flags: u16,
    payload: &[u8],
    now: Instant,
) -> Vec<Vec<u8>> {
    let segment = tcp::serialize(
        REMOTE_IP, LOCAL_IP, port, 8080, seq, ack, flags, 65_535, payload,
    );
    ip_to_stack(stack, ipv4::PROTOCOL_TCP, &segment, now)
}

fn connect(stack: &mut Stack, port: u16, now: Instant) -> (u32, u32) {
    let client_isn = 100_000 + u32::from(port);
    let replies = tcp_send(stack, port, client_isn, 0, tcp::SYN, &[], now);
    assert_eq!(replies.len(), 1);
    let syn_ack = parse_tcp_response(&replies[0]);
    assert_eq!(syn_ack.flags & (tcp::SYN | tcp::ACK), tcp::SYN | tcp::ACK);
    assert_eq!(syn_ack.acknowledgment, client_isn + 1);
    let client_seq = client_isn + 1;
    let server_seq = syn_ack.sequence + 1;
    assert!(tcp_send(stack, port, client_seq, server_seq, tcp::ACK, &[], now).is_empty());
    (client_seq, server_seq)
}

#[test]
fn ethernet_arp_request_is_answered() {
    let mut stack = stack();
    let request = arp::Packet {
        operation: arp::REQUEST,
        sender_mac: REMOTE_MAC,
        sender_ip: REMOTE_IP,
        target_mac: [0; 6],
        target_ip: LOCAL_IP,
    };
    let frame = ethernet::serialize(
        [0xff; 6],
        REMOTE_MAC,
        ethernet::ETHERTYPE_ARP,
        &request.serialize(),
    );
    let replies = stack.process_ethernet(&frame, Instant::now());
    let frame = ethernet::Frame::parse(&replies[0]).unwrap();
    let reply = arp::Packet::parse(frame.payload).unwrap();
    assert_eq!(frame.dst, REMOTE_MAC);
    assert_eq!(reply.operation, arp::REPLY);
    assert_eq!(reply.sender_ip, LOCAL_IP);
    assert_eq!(reply.sender_mac, LOCAL_MAC);
}

#[test]
fn arp_for_another_ip_is_ignored() {
    let mut stack = stack();
    let request = arp::Packet {
        operation: arp::REQUEST,
        sender_mac: REMOTE_MAC,
        sender_ip: REMOTE_IP,
        target_mac: [0; 6],
        target_ip: [10, 0, 0, 99],
    };
    let frame = ethernet::serialize(
        [0xff; 6],
        REMOTE_MAC,
        ethernet::ETHERTYPE_ARP,
        &request.serialize(),
    );
    assert!(stack.process_ethernet(&frame, Instant::now()).is_empty());
}

#[test]
fn icmp_echo_preserves_identifier_sequence_and_payload() {
    let mut stack = stack();
    let request = icmp::serialize(icmp::ECHO_REQUEST, 0, [0x12, 0x34, 0, 7], b"forty-two");
    let replies = ip_to_stack(&mut stack, ipv4::PROTOCOL_ICMP, &request, Instant::now());
    let ip = ipv4::Packet::parse(&replies[0]).unwrap();
    let reply = icmp::Packet::parse(ip.payload).unwrap();
    assert_eq!(reply.kind, icmp::ECHO_REPLY);
    assert_eq!(reply.rest, [0x12, 0x34, 0, 7]);
    assert_eq!(reply.payload, b"forty-two");
}

#[test]
fn corrupt_icmp_checksum_is_rejected() {
    let mut stack = stack();
    let mut request = icmp::serialize(icmp::ECHO_REQUEST, 0, [0; 4], b"bad");
    request[2] ^= 1;
    assert!(ip_to_stack(&mut stack, ipv4::PROTOCOL_ICMP, &request, Instant::now()).is_empty());
}

#[test]
fn udp_echo_round_trip() {
    let mut stack = stack();
    let request = udp::serialize(REMOTE_IP, LOCAL_IP, 40_000, 7, b"datagram");
    let replies = ip_to_stack(&mut stack, ipv4::PROTOCOL_UDP, &request, Instant::now());
    let ip = ipv4::Packet::parse(&replies[0]).unwrap();
    let reply = udp::Datagram::parse(LOCAL_IP, REMOTE_IP, ip.payload).unwrap();
    assert_eq!((reply.src_port, reply.dst_port), (7, 40_000));
    assert_eq!(reply.payload, b"datagram");
}

#[test]
fn udp_closed_port_records_event_without_reply() {
    let mut stack = stack();
    let request = udp::serialize(REMOTE_IP, LOCAL_IP, 40_000, 9999, b"observe");
    assert!(ip_to_stack(&mut stack, ipv4::PROTOCOL_UDP, &request, Instant::now()).is_empty());
    assert!(matches!(
        stack.drain_events().next(),
        Some(StackEvent::UdpDatagram {
            local_port: 9999,
            ..
        })
    ));
}

#[test]
fn corrupt_udp_checksum_is_rejected() {
    let mut stack = stack();
    let mut request = udp::serialize(REMOTE_IP, LOCAL_IP, 40_000, 7, b"bad");
    request[6] ^= 1;
    assert!(ip_to_stack(&mut stack, ipv4::PROTOCOL_UDP, &request, Instant::now()).is_empty());
}

#[test]
fn packet_for_another_ipv4_address_is_ignored() {
    let mut stack = stack();
    let echo = icmp::serialize(icmp::ECHO_REQUEST, 0, [0; 4], b"hello");
    let ip = ipv4::serialize(REMOTE_IP, [10, 0, 0, 99], ipv4::PROTOCOL_ICMP, 1, &echo);
    assert!(stack.process_ipv4_packet(&ip, Instant::now()).is_empty());
}

#[test]
fn fragmented_ipv4_packet_is_rejected() {
    let echo = icmp::serialize(icmp::ECHO_REQUEST, 0, [0; 4], b"hello");
    let mut ip = ipv4::serialize(REMOTE_IP, LOCAL_IP, ipv4::PROTOCOL_ICMP, 1, &echo);
    ip[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
    ip[10..12].fill(0);
    let sum = userspace_stack::checksum::internet(&ip[..20]);
    ip[10..12].copy_from_slice(&sum.to_be_bytes());
    assert!(matches!(
        ipv4::Packet::parse(&ip),
        Err(ipv4::ParseError::Fragmented)
    ));
}

#[test]
fn tcp_three_way_handshake_establishes_connection() {
    let mut stack = stack();
    connect(&mut stack, 30_000, Instant::now());
    assert_eq!(stack.connection_count(), 1);
    assert!(
        stack
            .drain_events()
            .any(|event| matches!(event, StackEvent::Tcp(tcp::Event::Established(_))))
    );
}

#[test]
fn tcp_payload_is_acknowledged_and_echoed() {
    let mut stack = stack();
    let now = Instant::now();
    let (client_seq, server_seq) = connect(&mut stack, 30_001, now);
    let replies = tcp_send(
        &mut stack,
        30_001,
        client_seq,
        server_seq,
        tcp::ACK | tcp::PSH,
        b"stream",
        now,
    );
    let reply = parse_tcp_response(&replies[0]);
    assert_eq!(reply.payload, b"stream");
    assert_eq!(reply.sequence, server_seq);
    assert_eq!(reply.acknowledgment, client_seq + 6);
}

#[test]
fn duplicate_tcp_payload_is_only_acknowledged() {
    let mut stack = stack();
    let now = Instant::now();
    let (client_seq, server_seq) = connect(&mut stack, 30_002, now);
    let first = tcp_send(
        &mut stack,
        30_002,
        client_seq,
        server_seq,
        tcp::ACK | tcp::PSH,
        b"once",
        now,
    );
    assert_eq!(parse_tcp_response(&first[0]).payload, b"once");
    let duplicate = tcp_send(
        &mut stack,
        30_002,
        client_seq,
        server_seq,
        tcp::ACK | tcp::PSH,
        b"once",
        now,
    );
    let ack = parse_tcp_response(&duplicate[0]);
    assert!(ack.payload.is_empty());
    assert_eq!(ack.acknowledgment, client_seq + 4);
}

#[test]
fn tcp_fin_handshake_removes_connection() {
    let mut stack = stack();
    let now = Instant::now();
    let (client_seq, server_seq) = connect(&mut stack, 30_003, now);
    let replies = tcp_send(
        &mut stack,
        30_003,
        client_seq,
        server_seq,
        tcp::FIN | tcp::ACK,
        &[],
        now,
    );
    let fin_ack = parse_tcp_response(&replies[0]);
    assert_eq!(fin_ack.flags & (tcp::FIN | tcp::ACK), tcp::FIN | tcp::ACK);
    assert_eq!(fin_ack.acknowledgment, client_seq + 1);
    assert!(
        tcp_send(
            &mut stack,
            30_003,
            client_seq + 1,
            server_seq + 1,
            tcp::ACK,
            &[],
            now
        )
        .is_empty()
    );
    assert_eq!(stack.connection_count(), 0);
}

#[test]
fn tcp_reset_removes_connection() {
    let mut stack = stack();
    let now = Instant::now();
    let (client_seq, server_seq) = connect(&mut stack, 30_004, now);
    tcp_send(
        &mut stack,
        30_004,
        client_seq,
        server_seq,
        tcp::RST | tcp::ACK,
        &[],
        now,
    );
    assert_eq!(stack.connection_count(), 0);
    assert!(
        stack
            .drain_events()
            .any(|event| matches!(event, StackEvent::Tcp(tcp::Event::Reset(_))))
    );
}

#[test]
fn unacknowledged_syn_ack_is_retransmitted_with_backoff() {
    let mut stack = stack();
    let now = Instant::now();
    let replies = tcp_send(&mut stack, 30_005, 123, 0, tcp::SYN, &[], now);
    let original = parse_tcp_response(&replies[0]);
    assert!(stack.tick_ipv4(now + Duration::from_millis(199)).is_empty());
    let retried = stack.tick_ipv4(now + Duration::from_millis(200));
    let retry = parse_tcp_response(&retried[0]);
    assert_eq!(retry.sequence, original.sequence);
    assert!(stack.tick_ipv4(now + Duration::from_millis(599)).is_empty());
    assert_eq!(stack.tick_ipv4(now + Duration::from_millis(600)).len(), 1);
}

#[test]
fn syn_to_unlisted_tcp_port_is_ignored() {
    let mut stack = stack();
    let segment = tcp::serialize(
        REMOTE_IP,
        LOCAL_IP,
        30_006,
        9090,
        1,
        0,
        tcp::SYN,
        65_535,
        &[],
    );
    assert!(ip_to_stack(&mut stack, ipv4::PROTOCOL_TCP, &segment, Instant::now()).is_empty());
}

#[test]
fn corrupt_tcp_checksum_is_rejected() {
    let mut stack = stack();
    let mut segment = tcp::serialize(
        REMOTE_IP,
        LOCAL_IP,
        30_007,
        8080,
        1,
        0,
        tcp::SYN,
        65_535,
        &[],
    );
    segment[16] ^= 1;
    assert!(ip_to_stack(&mut stack, ipv4::PROTOCOL_TCP, &segment, Instant::now()).is_empty());
}

#[test]
fn tcp_sink_acknowledges_without_echoing() {
    let mut stack = Stack::new(Config {
        tcp_sink_ports: vec![8080],
        ..Config::default()
    });
    let now = Instant::now();
    let (client_seq, server_seq) = connect(&mut stack, 30_008, now);
    let replies = tcp_send(
        &mut stack,
        30_008,
        client_seq,
        server_seq,
        tcp::ACK | tcp::PSH,
        b"discard me",
        now,
    );
    let reply = parse_tcp_response(&replies[0]);
    assert!(reply.payload.is_empty());
    assert_eq!(reply.acknowledgment, client_seq + 10);
}

#[test]
fn tcp_sink_delays_ack_until_a_second_segment_or_timeout() {
    let mut stack = Stack::new(Config {
        tcp_sink_ports: vec![8080],
        ..Config::default()
    });
    let now = Instant::now();
    let (client_seq, server_seq) = connect(&mut stack, 30_010, now);

    assert!(
        tcp_send(
            &mut stack,
            30_010,
            client_seq,
            server_seq,
            tcp::ACK,
            b"first",
            now,
        )
        .is_empty()
    );
    assert!(stack.tick_ipv4(now + Duration::from_millis(9)).is_empty());
    let delayed = stack.tick_ipv4(now + Duration::from_millis(10));
    assert_eq!(
        parse_tcp_response(&delayed[0]).acknowledgment,
        client_seq + 5
    );

    assert!(
        tcp_send(
            &mut stack,
            30_010,
            client_seq + 5,
            server_seq,
            tcp::ACK,
            b"second",
            now,
        )
        .is_empty()
    );
    let cumulative = tcp_send(
        &mut stack,
        30_010,
        client_seq + 11,
        server_seq,
        tcp::ACK,
        b"third",
        now,
    );
    assert_eq!(
        parse_tcp_response(&cumulative[0]).acknowledgment,
        client_seq + 16
    );
}

#[test]
fn stack_can_send_tcp_data_to_an_established_peer() {
    let mut stack = stack();
    let now = Instant::now();
    let (client_seq, server_seq) = connect(&mut stack, 30_009, now);
    let key = tcp::ConnectionKey {
        remote_ip: REMOTE_IP,
        remote_port: 30_009,
        local_port: 8080,
    };
    assert_eq!(stack.tcp_send_capacity(key), 65_535);

    let packet = stack.send_tcp_ipv4(key, b"from stack", now).unwrap();
    let sent = parse_tcp_response(&packet);
    assert_eq!(sent.sequence, server_seq);
    assert_eq!(sent.acknowledgment, client_seq);
    assert_eq!(sent.payload, b"from stack");
    assert_eq!(stack.tcp_send_capacity(key), 65_525);

    let ack = tcp_send(
        &mut stack,
        30_009,
        client_seq,
        server_seq + 10,
        tcp::ACK,
        &[],
        now,
    );
    assert!(ack.is_empty());
    assert_eq!(stack.tcp_send_capacity(key), 65_535);
}
