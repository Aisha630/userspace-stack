use crate::{MacAddr, arp, ethernet, icmp, ipv4, tcp, udp};
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Config {
    pub local_ip: [u8; 4],
    pub local_mac: MacAddr,
    pub tcp_listeners: Vec<u16>,
    pub udp_echo_ports: Vec<u16>,
    pub retransmission_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            local_ip: [10, 0, 0, 2],
            local_mac: [0x02, 0, 0, 0, 0, 2],
            tcp_listeners: vec![8080],
            udp_echo_ports: vec![7],
            retransmission_timeout: Duration::from_millis(200),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StackEvent {
    ArpLearned {
        ip: [u8; 4],
        mac: MacAddr,
    },
    IcmpEcho {
        remote_ip: [u8; 4],
        bytes: usize,
    },
    UdpDatagram {
        remote_ip: [u8; 4],
        remote_port: u16,
        local_port: u16,
        data: Vec<u8>,
    },
    Tcp(tcp::Event),
}

pub struct Stack {
    config: Config,
    tcp: tcp::Engine,
    arp_cache: HashMap<[u8; 4], MacAddr>,
    events: Vec<StackEvent>,
    next_ip_id: u16,
}

impl Stack {
    pub fn new(config: Config) -> Self {
        let tcp = tcp::Engine::new(
            config.local_ip,
            config.tcp_listeners.clone(),
            config.retransmission_timeout,
        );
        Self {
            config,
            tcp,
            arp_cache: HashMap::new(),
            events: Vec::new(),
            next_ip_id: 1,
        }
    }

    pub fn connection_count(&self) -> usize {
        self.tcp.connection_count()
    }

    pub fn drain_events(&mut self) -> impl Iterator<Item = StackEvent> + '_ {
        self.events.drain(..)
    }

    /// Processes one Ethernet frame (TAP mode) and returns response frames.
    pub fn process_ethernet(&mut self, bytes: &[u8], now: Instant) -> Vec<Vec<u8>> {
        let Some(frame) = ethernet::Frame::parse(bytes) else {
            return Vec::new();
        };
        if frame.dst != self.config.local_mac && frame.dst != [0xff; 6] {
            return Vec::new();
        }
        match frame.ethertype {
            ethernet::ETHERTYPE_ARP => self.handle_arp(frame.payload),
            ethernet::ETHERTYPE_IPV4 => {
                if let Ok(packet) = ipv4::Packet::parse(frame.payload) {
                    self.remember_peer(packet.src, frame.src);
                }
                self.process_ipv4_packet(frame.payload, now)
                    .into_iter()
                    .map(|packet| {
                        ethernet::serialize(
                            frame.src,
                            self.config.local_mac,
                            ethernet::ETHERTYPE_IPV4,
                            &packet,
                        )
                    })
                    .collect()
            }
            _ => Vec::new(),
        }
    }

    /// Processes one raw IPv4 packet (TUN mode) and returns response packets.
    pub fn process_ipv4_packet(&mut self, bytes: &[u8], now: Instant) -> Vec<Vec<u8>> {
        let Ok(packet) = ipv4::Packet::parse(bytes) else {
            return Vec::new();
        };
        if packet.dst != self.config.local_ip {
            return Vec::new();
        }
        let remote_ip = packet.src;
        let outputs: Vec<(u8, Vec<u8>)> = match packet.protocol {
            ipv4::PROTOCOL_ICMP => self.handle_icmp(remote_ip, packet.payload),
            ipv4::PROTOCOL_UDP => self.handle_udp(remote_ip, packet.payload),
            ipv4::PROTOCOL_TCP => self.handle_tcp(remote_ip, packet.payload, now),
            _ => Vec::new(),
        };
        outputs
            .into_iter()
            .map(|(protocol, payload)| self.wrap_ipv4(remote_ip, protocol, &payload))
            .collect()
    }

    /// Runs retransmission timers and returns Ethernet frames for known peers.
    pub fn tick_ethernet(&mut self, now: Instant) -> Vec<Vec<u8>> {
        self.tcp
            .tick(now)
            .into_iter()
            .filter_map(|out| {
                let mac = self.arp_cache.get(&out.key.remote_ip).copied()?;
                let ip = ipv4::serialize(
                    self.config.local_ip,
                    out.key.remote_ip,
                    ipv4::PROTOCOL_TCP,
                    self.take_ip_id(),
                    &out.bytes,
                );
                Some(ethernet::serialize(
                    mac,
                    self.config.local_mac,
                    ethernet::ETHERTYPE_IPV4,
                    &ip,
                ))
            })
            .collect()
    }

    /// Runs retransmission timers and returns raw IPv4 packets for TUN mode.
    pub fn tick_ipv4(&mut self, now: Instant) -> Vec<Vec<u8>> {
        self.tcp
            .tick(now)
            .into_iter()
            .map(|out| self.wrap_ipv4(out.key.remote_ip, ipv4::PROTOCOL_TCP, &out.bytes))
            .collect()
    }

    fn handle_arp(&mut self, bytes: &[u8]) -> Vec<Vec<u8>> {
        let Some(packet) = arp::Packet::parse(bytes) else {
            return Vec::new();
        };
        self.remember_peer(packet.sender_ip, packet.sender_mac);
        if packet.operation != arp::REQUEST || packet.target_ip != self.config.local_ip {
            return Vec::new();
        }
        let reply = arp::Packet {
            operation: arp::REPLY,
            sender_mac: self.config.local_mac,
            sender_ip: self.config.local_ip,
            target_mac: packet.sender_mac,
            target_ip: packet.sender_ip,
        };
        vec![ethernet::serialize(
            packet.sender_mac,
            self.config.local_mac,
            ethernet::ETHERTYPE_ARP,
            &reply.serialize(),
        )]
    }

    fn handle_icmp(&mut self, remote_ip: [u8; 4], bytes: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let Some(request) = icmp::Packet::parse(bytes) else {
            return Vec::new();
        };
        let Some(reply) = request.echo_reply() else {
            return Vec::new();
        };
        self.events.push(StackEvent::IcmpEcho {
            remote_ip,
            bytes: request.payload.len(),
        });
        vec![(ipv4::PROTOCOL_ICMP, reply)]
    }

    fn handle_udp(&mut self, remote_ip: [u8; 4], bytes: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let Some(datagram) = udp::Datagram::parse(remote_ip, self.config.local_ip, bytes) else {
            return Vec::new();
        };
        self.events.push(StackEvent::UdpDatagram {
            remote_ip,
            remote_port: datagram.src_port,
            local_port: datagram.dst_port,
            data: datagram.payload.to_vec(),
        });
        if !self.config.udp_echo_ports.contains(&datagram.dst_port) {
            return Vec::new();
        }
        vec![(
            ipv4::PROTOCOL_UDP,
            udp::serialize(
                self.config.local_ip,
                remote_ip,
                datagram.dst_port,
                datagram.src_port,
                datagram.payload,
            ),
        )]
    }

    fn handle_tcp(&mut self, remote_ip: [u8; 4], bytes: &[u8], now: Instant) -> Vec<(u8, Vec<u8>)> {
        let Some(segment) = tcp::Segment::parse(remote_ip, self.config.local_ip, bytes) else {
            return Vec::new();
        };
        let (outbound, events) = self.tcp.handle(remote_ip, &segment, now);
        self.events.extend(events.into_iter().map(StackEvent::Tcp));
        outbound
            .into_iter()
            .map(|out| (ipv4::PROTOCOL_TCP, out.bytes))
            .collect()
    }

    fn remember_peer(&mut self, ip: [u8; 4], mac: MacAddr) {
        if self.arp_cache.insert(ip, mac) != Some(mac) {
            self.events.push(StackEvent::ArpLearned { ip, mac });
        }
    }

    fn wrap_ipv4(&mut self, remote_ip: [u8; 4], protocol: u8, payload: &[u8]) -> Vec<u8> {
        let id = self.take_ip_id();
        ipv4::serialize(self.config.local_ip, remote_ip, protocol, id, payload)
    }

    fn take_ip_id(&mut self) -> u16 {
        let id = self.next_ip_id;
        self.next_ip_id = self.next_ip_id.wrapping_add(1);
        id
    }
}
