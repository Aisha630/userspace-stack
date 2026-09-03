#[cfg(target_os = "linux")]
mod linux {
    use std::cmp;
    use std::io::{self, Read, Write};
    use std::net::{Ipv4Addr, TcpStream};
    use std::process::Command;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};
    use userspace_stack::tcp::{self, ConnectionKey};
    use userspace_stack::tun::{Device, Mode};
    use userspace_stack::{Config, Stack, StackEvent};

    const READER_PORT: u16 = 1234;
    const WRITER_PORT: u16 = 1235;
    const DEFAULT_MIB: usize = 1024;
    const TCP_PAYLOAD: usize = 1460;

    #[derive(Clone, Copy)]
    enum Client {
        Reader,
        Writer,
    }

    struct Result {
        bytes: usize,
        elapsed: Duration,
    }

    pub fn run() -> io::Result<()> {
        let (client, mib, tap_name) = parse_args()?;
        let amount = mib
            .checked_mul(1024 * 1024)
            .ok_or_else(|| invalid_arg("--mib is too large"))?;
        if amount == 0 {
            return Err(invalid_arg("--mib must be greater than zero"));
        }

        let local_ip = Ipv4Addr::new(10, 0, 0, 2);
        let host_ip = Ipv4Addr::new(10, 0, 0, 1);
        let mut device = Device::create(&tap_name, Mode::Tap)?;
        run_ip(&[
            "addr",
            "replace",
            &format!("{host_ip}/24"),
            "dev",
            device.name(),
        ])?;
        run_ip(&["link", "set", "dev", device.name(), "up"])?;

        let mut stack = Stack::new(Config {
            local_ip: local_ip.octets(),
            tcp_listeners: vec![READER_PORT, WRITER_PORT],
            tcp_sink_ports: vec![READER_PORT, WRITER_PORT],
            ..Config::default()
        });
        let (result_tx, result_rx) = mpsc::channel();
        thread::spawn(move || {
            let result = run_client(client, local_ip, amount);
            let _ = result_tx.send(result);
        });

        let mut buffer = vec![0u8; 65_536];
        let mut source = None;
        let mut source_remaining = amount;
        loop {
            match result_rx.try_recv() {
                Ok(result) => {
                    let result = result?;
                    let gbps = result.bytes as f64 * 8.0 / result.elapsed.as_secs_f64() / 1e9;
                    println!("mode={}", client.name());
                    println!("payload_bytes={}", result.bytes);
                    println!("elapsed_seconds={:.6}", result.elapsed.as_secs_f64());
                    println!("throughput: {gbps:.3} Gbps");
                    return Ok(());
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    return Err(io::Error::other("benchmark client stopped unexpectedly"));
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }

            let now = Instant::now();
            loop {
                match device.read_packet(&mut buffer) {
                    Ok(size) => {
                        for response in stack.process_ethernet(&buffer[..size], now) {
                            device.write_packet(&response)?;
                        }
                        for event in stack.drain_events() {
                            if let StackEvent::Tcp(tcp::Event::Established(key)) = event {
                                if key.local_port == READER_PORT {
                                    source = Some(key);
                                }
                            }
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error),
                }
            }

            if let Some(key) = source {
                fill_send_window(&mut stack, &mut device, key, &mut source_remaining, now)?;
            }
            for packet in stack.tick_ethernet(now) {
                device.write_packet(&packet)?;
            }
            thread::yield_now();
        }
    }

    fn fill_send_window(
        stack: &mut Stack,
        device: &mut Device,
        key: ConnectionKey,
        remaining: &mut usize,
        now: Instant,
    ) -> io::Result<()> {
        while *remaining != 0 {
            let length = cmp::min(
                *remaining,
                cmp::min(TCP_PAYLOAD, stack.tcp_send_capacity(key)),
            );
            if length == 0 {
                break;
            }
            let payload = [0xa5; TCP_PAYLOAD];
            let frame = stack
                .send_tcp_ethernet(key, &payload[..length], now)
                .expect("send capacity was checked");
            device.write_packet(&frame)?;
            *remaining -= length;
        }
        Ok(())
    }

    fn run_client(client: Client, ip: Ipv4Addr, amount: usize) -> io::Result<Result> {
        let port = match client {
            Client::Reader => READER_PORT,
            Client::Writer => WRITER_PORT,
        };
        let mut stream = TcpStream::connect((ip, port))?;
        let mut buffer = vec![0u8; 1024 * 1024];
        let started = Instant::now();
        let mut processed = 0;
        while processed < amount {
            let length = cmp::min(buffer.len(), amount - processed);
            let count = match client {
                Client::Reader => stream.read(&mut buffer[..length])?,
                Client::Writer => stream.write(&buffer[..length])?,
            };
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "TCP connection closed before the transfer completed",
                ));
            }
            processed += count;
        }
        Ok(Result {
            bytes: processed,
            elapsed: started.elapsed(),
        })
    }

    impl Client {
        fn name(self) -> &'static str {
            match self {
                Self::Reader => "reader",
                Self::Writer => "writer",
            }
        }
    }

    fn parse_args() -> io::Result<(Client, usize, String)> {
        let mut client = None;
        let mut mib = DEFAULT_MIB;
        let mut tap_name = "tap-bench0".to_owned();
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "reader" if client.is_none() => client = Some(Client::Reader),
                "writer" if client.is_none() => client = Some(Client::Writer),
                "--mib" => {
                    mib = args
                        .next()
                        .ok_or_else(|| invalid_arg("--mib needs a value"))?
                        .parse()
                        .map_err(invalid_arg)?;
                }
                "--tap" => {
                    tap_name = args
                        .next()
                        .ok_or_else(|| invalid_arg("--tap needs a value"))?;
                }
                "--help" | "-h" => {
                    println!("tap-bench [--tap IFACE] [--mib MIB] [reader|writer]");
                    std::process::exit(0);
                }
                _ => return Err(invalid_arg(format!("unknown argument: {arg}"))),
            }
        }
        let client = client.ok_or_else(|| invalid_arg("choose reader or writer"))?;
        Ok((client, mib, tap_name))
    }

    fn invalid_arg(error: impl std::fmt::Display) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
    }

    fn run_ip(args: &[&str]) -> io::Result<()> {
        let status = Command::new("ip").args(args).status()?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!("ip {} failed", args.join(" "))))
        }
    }
}

#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    linux::run()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("tap-bench requires Linux and permission to create a TAP interface");
    std::process::exit(1);
}
