use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedPacket {
    pub id: usize,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub length: usize,

    // Layer 2 - Ethernet
    pub eth_src: Option<String>,
    pub eth_dst: Option<String>,
    pub eth_type: u16,

    // Layer 3 - IP
    pub ip_version: Option<u8>,
    pub ip_src: Option<IpAddr>,
    pub ip_dst: Option<IpAddr>,
    pub ip_protocol: Option<u8>,
    pub ip_ttl: Option<u8>,

    // Layer 4 - TCP/UDP
    pub transport_protocol: TransportProtocol,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,

    // TCP specific
    pub tcp_flags: Option<TcpFlags>,
    pub tcp_seq: Option<u32>,
    pub tcp_ack: Option<u32>,

    // Payload
    pub payload: Vec<u8>,
    pub payload_text: Option<String>,

    // Analysis
    pub service_hint: Option<String>,
    pub pattern_match: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

impl TransportProtocol {
    pub fn from_ip_protocol(proto: u8) -> Self {
        match proto {
            1 => TransportProtocol::Icmp,
            6 => TransportProtocol::Tcp,
            17 => TransportProtocol::Udp,
            _ => TransportProtocol::Other(proto),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            TransportProtocol::Tcp => "TCP",
            TransportProtocol::Udp => "UDP",
            TransportProtocol::Icmp => "ICMP",
            TransportProtocol::Other(_) => "OTHER",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

impl TcpFlags {
    pub fn from_byte(flags: u8) -> Self {
        Self {
            fin: flags & 0x01 != 0,
            syn: flags & 0x02 != 0,
            rst: flags & 0x04 != 0,
            psh: flags & 0x08 != 0,
            ack: flags & 0x10 != 0,
            urg: flags & 0x20 != 0,
            ece: flags & 0x40 != 0,
            cwr: flags & 0x80 != 0,
        }
    }

    pub fn to_string(&self) -> String {
        let mut flags = Vec::new();
        if self.syn { flags.push("SYN"); }
        if self.ack { flags.push("ACK"); }
        if self.fin { flags.push("FIN"); }
        if self.rst { flags.push("RST"); }
        if self.psh { flags.push("PSH"); }
        if self.urg { flags.push("URG"); }
        if self.ece { flags.push("ECE"); }
        if self.cwr { flags.push("CWR"); }
        if flags.is_empty() {
            "---".to_string()
        } else {
            flags.join(",")
        }
    }

    pub fn describe(&self) -> &'static str {
        if self.syn && !self.ack {
            "Connection initiation (SYN)"
        } else if self.syn && self.ack {
            "Connection acknowledgment (SYN-ACK)"
        } else if self.fin && self.ack {
            "Connection termination (FIN-ACK)"
        } else if self.rst {
            "Connection reset (RST)"
        } else if self.ack && self.psh {
            "Data push (PSH-ACK)"
        } else if self.ack {
            "Acknowledgment (ACK)"
        } else {
            "Unknown flag combination"
        }
    }
}

impl CapturedPacket {
    pub fn summary(&self) -> String {
        let proto = self.transport_protocol.as_str();
        let src = self.ip_src.map(|ip| format!("{}", ip)).unwrap_or_else(|| "?".to_string());
        let dst = self.ip_dst.map(|ip| format!("{}", ip)).unwrap_or_else(|| "?".to_string());
        let src_port = self.src_port.map(|p| p.to_string()).unwrap_or_else(|| "?".to_string());
        let dst_port = self.dst_port.map(|p| p.to_string()).unwrap_or_else(|| "?".to_string());

        format!(
            "{} {}:{} → {}:{} ({} bytes)",
            proto, src, src_port, dst, dst_port, self.length
        )
    }

    pub fn hex_dump(&self) -> String {
        let mut result = String::new();
        for (i, chunk) in self.payload.chunks(16).enumerate() {
            // Offset
            result.push_str(&format!("{:04x}  ", i * 16));

            // Hex bytes
            for (j, byte) in chunk.iter().enumerate() {
                result.push_str(&format!("{:02x} ", byte));
                if j == 7 {
                    result.push(' ');
                }
            }

            // Padding for incomplete lines
            if chunk.len() < 16 {
                for j in chunk.len()..16 {
                    result.push_str("   ");
                    if j == 7 {
                        result.push(' ');
                    }
                }
            }

            // ASCII representation
            result.push_str(" |");
            for byte in chunk {
                if byte.is_ascii_graphic() || *byte == b' ' {
                    result.push(*byte as char);
                } else {
                    result.push('.');
                }
            }
            result.push_str("|\n");
        }
        result
    }

    pub fn ascii_dump(&self) -> String {
        self.payload
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b.is_ascii_whitespace() {
                    b as char
                } else {
                    '.'
                }
            })
            .collect()
    }
}
