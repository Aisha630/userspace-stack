use crate::{MacAddr, arp, checksum, ethernet, icmp, ipv4, tcp, udp};
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Config {
    pub local_ip: [u8; 4],
    pub local_mac: MacAddr,
    pub tcp_listeners: Vec<u16>,
    /// TCP listener ports that acknowledge and discard data instead of echoing it.
    pub tcp_sink_ports: Vec<u16>,
    pub udp_echo_ports: Vec<u16>,
    pub retransmission_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            local_ip: [10, 0, 0, 2],
            local_mac: [0x02, 0, 0, 0, 0, 2],
            tcp_listeners: vec![8080],
            tcp_sink_ports: Vec::new(),
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
    last_peer: Option<([u8; 4], MacAddr)>,
    events: Vec<StackEvent>,
    next_ip_id: u16,
}

impl Stack {
    pub fn new(config: Config) -> Self {
        let tcp = tcp::Engine::new(
            config.local_ip,
            config.tcp_listeners.clone(),
            config.tcp_sink_ports.clone(),
            config.retransmission_timeout,
        );
        Self {
            config,
            tcp,
            arp_cache: HashMap::new(),
            last_peer: None,
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

    /// Returns how many bytes can currently be queued for an established TCP peer.
    pub fn tcp_send_capacity(&self, key: tcp::ConnectionKey) -> usize {
        self.tcp.send_capacity(key)
    }

    /// Queues application data and returns a raw IPv4 packet for TUN mode.
    pub fn send_tcp_ipv4(
        &mut self,
        key: tcp::ConnectionKey,
        payload: &[u8],
        now: Instant,
    ) -> Option<Vec<u8>> {
        let output = self.tcp.send(key, payload, now)?;
        Some(self.wrap_ipv4(key.remote_ip, ipv4::PROTOCOL_TCP, &output.bytes))
    }

    /// Queues application data and returns an Ethernet frame for TAP mode.
    pub fn send_tcp_ethernet(
        &mut self,
        key: tcp::ConnectionKey,
        payload: &[u8],
        now: Instant,
    ) -> Option<Vec<u8>> {
        let remote_mac = self.peer_mac(key.remote_ip)?;
        let output = self.tcp.send(key, payload, now)?;
        Some(self.wrap_ethernet_ipv4(remote_mac, key.remote_ip, ipv4::PROTOCOL_TCP, &output.bytes))
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
                let Ok(packet) = ipv4::Packet::parse(frame.payload) else {
                    return Vec::new();
                };
                self.remember_peer(packet.src, frame.src);
                let remote_ip = packet.src;
                self.process_parsed_ipv4(packet, now)
                    .into_iter()
                    .map(|(protocol, payload)| {
                        self.wrap_ethernet_ipv4(frame.src, remote_ip, protocol, &payload)
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
        let remote_ip = packet.src;
        self.process_parsed_ipv4(packet, now)
            .into_iter()
            .map(|(protocol, payload)| self.wrap_ipv4(remote_ip, protocol, &payload))
            .collect()
    }

    fn process_parsed_ipv4(
        &mut self,
        packet: ipv4::Packet<'_>,
        now: Instant,
    ) -> Option<(u8, Vec<u8>)> {
        if packet.dst != self.config.local_ip {
            return None;
        }
        let remote_ip = packet.src;
        match packet.protocol {
            ipv4::PROTOCOL_ICMP => self.handle_icmp(remote_ip, packet.payload),
            ipv4::PROTOCOL_UDP => self.handle_udp(remote_ip, packet.payload),
            ipv4::PROTOCOL_TCP => self.handle_tcp(remote_ip, packet.payload, now),
            _ => None,
        }
    }

    /// Runs retransmission timers and returns Ethernet frames for known peers.
    pub fn tick_ethernet(&mut self, now: Instant) -> Vec<Vec<u8>> {
        self.tcp
            .tick(now)
            .into_iter()
            .filter_map(|out| {
                let mac = self.peer_mac(out.key.remote_ip)?;
                Some(self.wrap_ethernet_ipv4(
                    mac,
                    out.key.remote_ip,
                    ipv4::PROTOCOL_TCP,
                    &out.bytes,
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

    fn handle_icmp(&mut self, remote_ip: [u8; 4], bytes: &[u8]) -> Option<(u8, Vec<u8>)> {
        let request = icmp::Packet::parse(bytes)?;
        let reply = request.echo_reply()?;
        self.events.push(StackEvent::IcmpEcho {
            remote_ip,
            bytes: request.payload.len(),
        });
        Some((ipv4::PROTOCOL_ICMP, reply))
    }

    fn handle_udp(&mut self, remote_ip: [u8; 4], bytes: &[u8]) -> Option<(u8, Vec<u8>)> {
        let datagram = udp::Datagram::parse(remote_ip, self.config.local_ip, bytes)?;
        self.events.push(StackEvent::UdpDatagram {
            remote_ip,
            remote_port: datagram.src_port,
            local_port: datagram.dst_port,
            data: datagram.payload.to_vec(),
        });
        if !self.config.udp_echo_ports.contains(&datagram.dst_port) {
            return None;
        }
        Some((
            ipv4::PROTOCOL_UDP,
            udp::serialize(
                self.config.local_ip,
                remote_ip,
                datagram.dst_port,
                datagram.src_port,
                datagram.payload,
            ),
        ))
    }

    fn handle_tcp(
        &mut self,
        remote_ip: [u8; 4],
        bytes: &[u8],
        now: Instant,
    ) -> Option<(u8, Vec<u8>)> {
        let segment = tcp::Segment::parse(remote_ip, self.config.local_ip, bytes)?;
        let (outbound, events) = self.tcp.handle(remote_ip, &segment, now);
        self.events.extend(events.into_iter().map(StackEvent::Tcp));
        outbound.map(|out| (ipv4::PROTOCOL_TCP, out.bytes))
    }

    fn remember_peer(&mut self, ip: [u8; 4], mac: MacAddr) {
        if self.last_peer == Some((ip, mac)) {
            return;
        }
        self.last_peer = Some((ip, mac));
        if self.arp_cache.insert(ip, mac) != Some(mac) {
            self.events.push(StackEvent::ArpLearned { ip, mac });
        }
    }

    fn peer_mac(&self, ip: [u8; 4]) -> Option<MacAddr> {
        self.last_peer
            .filter(|(peer_ip, _)| *peer_ip == ip)
            .map(|(_, mac)| mac)
            .or_else(|| self.arp_cache.get(&ip).copied())
    }

    fn wrap_ipv4(&mut self, remote_ip: [u8; 4], protocol: u8, payload: &[u8]) -> Vec<u8> {
        let id = self.take_ip_id();
        ipv4::serialize(self.config.local_ip, remote_ip, protocol, id, payload)
    }

    fn wrap_ethernet_ipv4(
        &mut self,
        remote_mac: MacAddr,
        remote_ip: [u8; 4],
        protocol: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        const IPV4_HEADER_LEN: usize = 20;
        let ip_len = IPV4_HEADER_LEN + payload.len();
        assert!(ip_len <= u16::MAX as usize);

        let mut bytes = vec![0u8; ethernet::HEADER_LEN + ip_len];
        bytes[0..6].copy_from_slice(&remote_mac);
        bytes[6..12].copy_from_slice(&self.config.local_mac);
        bytes[12..14].copy_from_slice(&ethernet::ETHERTYPE_IPV4.to_be_bytes());

        let ip = &mut bytes[ethernet::HEADER_LEN..ethernet::HEADER_LEN + IPV4_HEADER_LEN];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
        ip[4..6].copy_from_slice(&self.take_ip_id().to_be_bytes());
        ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        ip[8] = 64;
        ip[9] = protocol;
        ip[12..16].copy_from_slice(&self.config.local_ip);
        ip[16..20].copy_from_slice(&remote_ip);
        let sum = checksum::internet(ip);
        ip[10..12].copy_from_slice(&sum.to_be_bytes());
        bytes[ethernet::HEADER_LEN + IPV4_HEADER_LEN..].copy_from_slice(payload);
        bytes
    }

    fn take_ip_id(&mut self) -> u16 {
        let id = self.next_ip_id;
        self.next_ip_id = self.next_ip_id.wrapping_add(1);
        id
    }
}
