use crate::checksum;
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub const FIN: u16 = 0x001;
pub const SYN: u16 = 0x002;
pub const RST: u16 = 0x004;
pub const PSH: u16 = 0x008;
pub const ACK: u16 = 0x010;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub sequence: u32,
    pub acknowledgment: u32,
    pub flags: u16,
    pub window: u16,
    pub payload: &'a [u8],
}

impl<'a> Segment<'a> {
    pub fn parse(src: [u8; 4], dst: [u8; 4], bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() < 20 || checksum::pseudo_header(src, dst, 6, bytes) != 0 {
            return None;
        }
        let header_len = ((bytes[12] >> 4) as usize) * 4;
        if header_len < 20 || header_len > bytes.len() {
            return None;
        }
        Some(Self {
            src_port: u16::from_be_bytes([bytes[0], bytes[1]]),
            dst_port: u16::from_be_bytes([bytes[2], bytes[3]]),
            sequence: u32::from_be_bytes(bytes[4..8].try_into().ok()?),
            acknowledgment: u32::from_be_bytes(bytes[8..12].try_into().ok()?),
            flags: u16::from_be_bytes([bytes[12] & 1, bytes[13]]),
            window: u16::from_be_bytes([bytes[14], bytes[15]]),
            payload: &bytes[header_len..],
        })
    }
}

#[allow(clippy::too_many_arguments)]
pub fn serialize(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    sequence: u32,
    acknowledgment: u32,
    flags: u16,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut bytes = vec![0u8; 20];
    bytes[0..2].copy_from_slice(&src_port.to_be_bytes());
    bytes[2..4].copy_from_slice(&dst_port.to_be_bytes());
    bytes[4..8].copy_from_slice(&sequence.to_be_bytes());
    bytes[8..12].copy_from_slice(&acknowledgment.to_be_bytes());
    bytes[12] = (5 << 4) | ((flags >> 8) as u8 & 1);
    bytes[13] = flags as u8;
    bytes[14..16].copy_from_slice(&window.to_be_bytes());
    bytes.extend_from_slice(payload);
    let sum = checksum::pseudo_header(src_ip, dst_ip, 6, &bytes);
    bytes[16..18].copy_from_slice(&sum.to_be_bytes());
    bytes
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct ConnectionKey {
    pub remote_ip: [u8; 4],
    pub remote_port: u16,
    pub local_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    SynReceived,
    Established,
    LastAck,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Established(ConnectionKey),
    Data(ConnectionKey, Vec<u8>),
    Closed(ConnectionKey),
    Reset(ConnectionKey),
}

#[derive(Debug, Clone)]
struct Outstanding {
    sequence: u32,
    end_sequence: u32,
    flags: u16,
    payload: Vec<u8>,
    last_sent: Instant,
    retries: u8,
}

#[derive(Debug, Clone)]
struct Connection {
    state: State,
    recv_next: u32,
    send_next: u32,
    peer_window: u16,
    outstanding: Vec<Outstanding>,
}

#[derive(Debug, Clone)]
pub struct Outbound {
    pub key: ConnectionKey,
    pub bytes: Vec<u8>,
    pub retransmission: bool,
}

pub struct Engine {
    local_ip: [u8; 4],
    listeners: Vec<u16>,
    sink_ports: Vec<u16>,
    connections: HashMap<ConnectionKey, Connection>,
    rto: Duration,
}

impl Engine {
    pub fn new(
        local_ip: [u8; 4],
        listeners: Vec<u16>,
        sink_ports: Vec<u16>,
        rto: Duration,
    ) -> Self {
        Self {
            local_ip,
            listeners,
            sink_ports,
            connections: HashMap::new(),
            rto,
        }
    }

    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    pub fn state(&self, key: ConnectionKey) -> Option<State> {
        self.connections.get(&key).map(|c| c.state)
    }

    pub fn send_capacity(&self, key: ConnectionKey) -> usize {
        let Some(connection) = self.connections.get(&key) else {
            return 0;
        };
        if connection.state != State::Established {
            return 0;
        }
        let in_flight = connection
            .outstanding
            .iter()
            .map(|sent| sent.end_sequence.wrapping_sub(sent.sequence) as usize)
            .sum::<usize>();
        usize::from(connection.peer_window).saturating_sub(in_flight)
    }

    pub fn send(&mut self, key: ConnectionKey, payload: &[u8], now: Instant) -> Option<Outbound> {
        if payload.is_empty() || payload.len() > self.send_capacity(key) {
            return None;
        }
        let connection = self.connections.get_mut(&key)?;
        let sequence = connection.send_next;
        connection.send_next = connection.send_next.wrapping_add(payload.len() as u32);
        connection.outstanding.push(Outstanding {
            sequence,
            end_sequence: connection.send_next,
            flags: ACK | PSH,
            payload: payload.to_vec(),
            last_sent: now,
            retries: 0,
        });
        Some(Outbound {
            key,
            bytes: make_segment(
                self.local_ip,
                key,
                sequence,
                connection.recv_next,
                ACK | PSH,
                payload,
            ),
            retransmission: false,
        })
    }

    pub fn handle(
        &mut self,
        remote_ip: [u8; 4],
        segment: &Segment<'_>,
        now: Instant,
    ) -> (Vec<Outbound>, Vec<Event>) {
        let key = ConnectionKey {
            remote_ip,
            remote_port: segment.src_port,
            local_port: segment.dst_port,
        };

        if segment.flags & RST != 0 {
            let existed = self.connections.remove(&key).is_some();
            return (
                Vec::new(),
                existed.then_some(Event::Reset(key)).into_iter().collect(),
            );
        }

        if !self.connections.contains_key(&key) {
            if segment.flags & SYN == 0 || !self.listeners.contains(&segment.dst_port) {
                return (Vec::new(), Vec::new());
            }
            let iss = initial_sequence(key);
            let mut connection = Connection {
                state: State::SynReceived,
                recv_next: segment.sequence.wrapping_add(1),
                send_next: iss.wrapping_add(1),
                peer_window: segment.window,
                outstanding: Vec::new(),
            };
            let bytes = make_segment(
                self.local_ip,
                key,
                iss,
                connection.recv_next,
                SYN | ACK,
                &[],
            );
            connection.outstanding.push(Outstanding {
                sequence: iss,
                end_sequence: iss.wrapping_add(1),
                flags: SYN | ACK,
                payload: Vec::new(),
                last_sent: now,
                retries: 0,
            });
            self.connections.insert(key, connection);
            return (
                vec![Outbound {
                    key,
                    bytes,
                    retransmission: false,
                }],
                Vec::new(),
            );
        }

        let connection = self.connections.get_mut(&key).expect("connection exists");
        connection.peer_window = segment.window;
        if segment.flags & ACK != 0 {
            connection
                .outstanding
                .retain(|sent| !seq_at_or_after(segment.acknowledgment, sent.end_sequence));
        }

        let mut events = Vec::new();
        let mut response: Option<(u32, u16, Vec<u8>)> = None;
        let mut remove = false;

        match connection.state {
            State::SynReceived => {
                if segment.flags & ACK != 0 && segment.acknowledgment == connection.send_next {
                    connection.state = State::Established;
                    events.push(Event::Established(key));
                }
            }
            State::Established => {
                let expected = connection.recv_next;
                if !segment.payload.is_empty() && segment.sequence == expected {
                    connection.recv_next = connection
                        .recv_next
                        .wrapping_add(segment.payload.len() as u32);
                    if self.sink_ports.contains(&key.local_port) {
                        response = Some((connection.send_next, ACK, Vec::new()));
                    } else {
                        events.push(Event::Data(key, segment.payload.to_vec()));
                        let sequence = connection.send_next;
                        connection.send_next = connection
                            .send_next
                            .wrapping_add(segment.payload.len() as u32);
                        response = Some((sequence, ACK | PSH, segment.payload.to_vec()));
                    }
                } else if !segment.payload.is_empty() {
                    response = Some((connection.send_next, ACK, Vec::new()));
                }

                let fin_sequence = segment.sequence.wrapping_add(segment.payload.len() as u32);
                if segment.flags & FIN != 0 && fin_sequence == connection.recv_next {
                    connection.recv_next = connection.recv_next.wrapping_add(1);
                    let sequence = connection.send_next;
                    connection.send_next = connection.send_next.wrapping_add(1);
                    connection.state = State::LastAck;
                    response = Some((sequence, FIN | ACK, Vec::new()));
                }
            }
            State::LastAck => {
                if segment.flags & ACK != 0
                    && seq_at_or_after(segment.acknowledgment, connection.send_next)
                {
                    events.push(Event::Closed(key));
                    remove = true;
                }
            }
        }

        let outbound = response.map(|(sequence, flags, payload)| {
            let bytes = make_segment(
                self.local_ip,
                key,
                sequence,
                connection.recv_next,
                flags,
                &payload,
            );
            if flags & (SYN | FIN) != 0 || !payload.is_empty() {
                let sequence_space = payload.len() as u32
                    + u32::from(flags & SYN != 0)
                    + u32::from(flags & FIN != 0);
                connection.outstanding.push(Outstanding {
                    sequence,
                    end_sequence: sequence.wrapping_add(sequence_space),
                    flags,
                    payload,
                    last_sent: now,
                    retries: 0,
                });
            }
            Outbound {
                key,
                bytes,
                retransmission: false,
            }
        });

        if remove {
            self.connections.remove(&key);
        }
        (outbound.into_iter().collect(), events)
    }

    pub fn tick(&mut self, now: Instant) -> Vec<Outbound> {
        let mut result = Vec::new();
        for (&key, connection) in &mut self.connections {
            for sent in &mut connection.outstanding {
                let backoff = self.rto.saturating_mul(1u32 << sent.retries.min(5));
                if now.duration_since(sent.last_sent) >= backoff {
                    result.push(Outbound {
                        key,
                        bytes: make_segment(
                            self.local_ip,
                            key,
                            sent.sequence,
                            connection.recv_next,
                            sent.flags,
                            &sent.payload,
                        ),
                        retransmission: true,
                    });
                    sent.last_sent = now;
                    sent.retries = sent.retries.saturating_add(1);
                }
            }
        }
        result
    }
}

fn make_segment(
    local_ip: [u8; 4],
    key: ConnectionKey,
    sequence: u32,
    acknowledgment: u32,
    flags: u16,
    payload: &[u8],
) -> Vec<u8> {
    serialize(
        local_ip,
        key.remote_ip,
        key.local_port,
        key.remote_port,
        sequence,
        acknowledgment,
        flags,
        65_535,
        payload,
    )
}

fn initial_sequence(key: ConnectionKey) -> u32 {
    let ip = u32::from_be_bytes(key.remote_ip);
    ip.rotate_left(13)
        ^ (u32::from(key.remote_port) << 16)
        ^ u32::from(key.local_port)
        ^ 0x6d2b_79f5
}

fn seq_at_or_after(value: u32, expected: u32) -> bool {
    value.wrapping_sub(expected) < (1 << 31)
}
