//! A small, dependency-free userspace TCP/IP stack.
//!
//! The protocol engine is independent from its device backend, which makes it
//! possible to run deterministic tests in memory and attach the same engine to
//! Linux TUN/TAP in production.

pub mod arp;
pub mod checksum;
pub mod ethernet;
pub mod icmp;
pub mod ipv4;
pub mod stack;
pub mod tcp;
pub mod tun;
pub mod udp;

pub use stack::{Config, Stack, StackEvent};

pub type MacAddr = [u8; 6];
