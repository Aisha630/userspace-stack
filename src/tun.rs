#[cfg(not(target_os = "linux"))]
use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Tun,
    Tap,
}

#[cfg(target_os = "linux")]
mod linux {
    use super::Mode;
    use std::fs::{File, OpenOptions};
    use std::io::{self, Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    const IFNAMSIZ: usize = 16;
    const IFF_TUN: i16 = 0x0001;
    const IFF_TAP: i16 = 0x0002;
    const IFF_NO_PI: i16 = 0x1000;
    const TUNSETIFF: usize = 0x4004_54ca;
    const O_NONBLOCK: i32 = 0x800;

    unsafe extern "C" {
        fn ioctl(fd: i32, request: usize, ...) -> i32;
    }

    pub struct Device {
        file: File,
        name: String,
        mode: Mode,
    }

    impl Device {
        pub fn create(requested_name: &str, mode: Mode) -> io::Result<Self> {
            if requested_name.as_bytes().len() >= IFNAMSIZ {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "interface name is too long",
                ));
            }
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(O_NONBLOCK)
                .open("/dev/net/tun")?;
            let mut ifreq = [0u8; 40];
            ifreq[..requested_name.len()].copy_from_slice(requested_name.as_bytes());
            let flags = match mode {
                Mode::Tun => IFF_TUN,
                Mode::Tap => IFF_TAP,
            } | IFF_NO_PI;
            ifreq[IFNAMSIZ..IFNAMSIZ + 2].copy_from_slice(&flags.to_ne_bytes());
            // SAFETY: ifreq is a writable buffer matching Linux's struct ifreq size;
            // the file descriptor refers to /dev/net/tun for the lifetime of the call.
            if unsafe { ioctl(file.as_raw_fd(), TUNSETIFF, ifreq.as_mut_ptr()) } < 0 {
                return Err(io::Error::last_os_error());
            }
            let name_len = ifreq[..IFNAMSIZ]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(IFNAMSIZ);
            let name = String::from_utf8_lossy(&ifreq[..name_len]).into_owned();
            Ok(Self { file, name, mode })
        }

        pub fn name(&self) -> &str {
            &self.name
        }
        pub fn mode(&self) -> Mode {
            self.mode
        }
        pub fn read_packet(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.file.read(buffer)
        }
        pub fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
            self.file.write_all(packet)
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::Device;

#[cfg(not(target_os = "linux"))]
pub struct Device;

#[cfg(not(target_os = "linux"))]
impl Device {
    pub fn create(_: &str, _: Mode) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TUN/TAP is only available on Linux",
        ))
    }
}
