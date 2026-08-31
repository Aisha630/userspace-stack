#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    use std::io;
    use std::net::Ipv4Addr;
    use std::process::Command;
    use std::thread;
    use std::time::{Duration, Instant};
    use userspace_stack::tun::{Device, Mode};
    use userspace_stack::{Config, Stack};

    let mut name = "tap0".to_owned();
    let mut mode = Mode::Tap;
    let mut local_ip = Ipv4Addr::new(10, 0, 0, 2);
    let mut host_ip = Ipv4Addr::new(10, 0, 0, 1);
    let mut tcp_port = 8080u16;
    let mut udp_port = 7u16;
    let mut configure = true;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let value = |args: &mut std::iter::Skip<std::env::Args>, flag: &str| {
            args.next().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("{flag} needs a value"))
            })
        };
        match arg.as_str() {
            "--tun" => mode = Mode::Tun,
            "--tap" => mode = Mode::Tap,
            "--name" => name = value(&mut args, "--name")?,
            "--ip" => local_ip = value(&mut args, "--ip")?.parse().map_err(invalid_arg)?,
            "--host-ip" => {
                host_ip = value(&mut args, "--host-ip")?
                    .parse()
                    .map_err(invalid_arg)?
            }
            "--tcp-port" => {
                tcp_port = value(&mut args, "--tcp-port")?
                    .parse()
                    .map_err(invalid_arg)?
            }
            "--udp-port" => {
                udp_port = value(&mut args, "--udp-port")?
                    .parse()
                    .map_err(invalid_arg)?
            }
            "--no-configure" => configure = false,
            "--help" | "-h" => {
                println!(
                    "ustack [--tap|--tun] [--name IFACE] [--ip IP] [--host-ip IP] [--tcp-port PORT] [--udp-port PORT] [--no-configure]"
                );
                return Ok(());
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown argument: {arg}"),
                ));
            }
        }
    }

    let mut device = Device::create(&name, mode)?;
    if configure {
        let prefix = format!("{host_ip}/24");
        run_ip(&["addr", "add", &prefix, "dev", device.name()])?;
        run_ip(&["link", "set", "dev", device.name(), "up"])?;
    }

    let config = Config {
        local_ip: local_ip.octets(),
        tcp_listeners: vec![tcp_port],
        udp_echo_ports: vec![udp_port],
        ..Config::default()
    };
    let mut stack = Stack::new(config);
    let mut buffer = vec![0u8; 65_536];
    eprintln!(
        "ustack: {:?} {} ready; stack IP {local_ip}, TCP {tcp_port}, UDP {udp_port}",
        device.mode(),
        device.name()
    );

    loop {
        let now = Instant::now();
        let mut did_work = false;
        loop {
            match device.read_packet(&mut buffer) {
                Ok(size) => {
                    did_work = true;
                    let responses = match mode {
                        Mode::Tap => stack.process_ethernet(&buffer[..size], now),
                        Mode::Tun => stack.process_ipv4_packet(&buffer[..size], now),
                    };
                    for response in responses {
                        device.write_packet(&response)?;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        let retransmissions = match mode {
            Mode::Tap => stack.tick_ethernet(now),
            Mode::Tun => stack.tick_ipv4(now),
        };
        for packet in retransmissions {
            device.write_packet(&packet)?;
        }
        if !did_work {
            thread::sleep(Duration::from_micros(100));
        }
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

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!(
        "ustack's TUN/TAP runner requires Linux; use `cargo run --release --bin stack-bench` for the portable in-memory benchmark"
    );
    std::process::exit(1);
}
