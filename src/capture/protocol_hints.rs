/// Protocol hints database for identifying common traffic patterns
/// This helps users understand what they're seeing in packet captures

pub struct ProtocolHint {
    pub name: &'static str,
    pub description: &'static str,
    pub common_ports: &'static [u16],
    pub indicators: &'static [&'static str],
    pub security_notes: &'static str,
}

pub static PROTOCOL_HINTS: &[ProtocolHint] = &[
    ProtocolHint {
        name: "HTTP",
        description: "Hypertext Transfer Protocol - Web traffic",
        common_ports: &[80, 8080, 8000, 8008, 3000],
        indicators: &["GET ", "POST ", "PUT ", "DELETE ", "HTTP/1", "HTTP/2"],
        security_notes: "Unencrypted. Credentials and data visible in plaintext. Consider HTTPS.",
    },
    ProtocolHint {
        name: "HTTPS/TLS",
        description: "Encrypted web traffic using TLS",
        common_ports: &[443, 8443],
        indicators: &["\x16\x03\x01", "\x16\x03\x03"], // TLS handshake
        security_notes: "Encrypted. Payload not visible but metadata (SNI, timing) may leak info.",
    },
    ProtocolHint {
        name: "DNS",
        description: "Domain Name System - Name resolution queries",
        common_ports: &[53],
        indicators: &[],
        security_notes: "Usually unencrypted. DNS queries reveal browsing patterns. Consider DoH/DoT.",
    },
    ProtocolHint {
        name: "SSH",
        description: "Secure Shell - Encrypted remote access",
        common_ports: &[22],
        indicators: &["SSH-2.0", "SSH-1"],
        security_notes: "Encrypted. Watch for brute-force attempts (many failed connections).",
    },
    ProtocolHint {
        name: "FTP",
        description: "File Transfer Protocol - File transfers",
        common_ports: &[20, 21],
        indicators: &["220 ", "USER ", "PASS ", "RETR ", "STOR "],
        security_notes: "Unencrypted! Credentials sent in plaintext. Use SFTP or FTPS instead.",
    },
    ProtocolHint {
        name: "SMTP",
        description: "Simple Mail Transfer Protocol - Email sending",
        common_ports: &[25, 465, 587],
        indicators: &["EHLO ", "HELO ", "MAIL FROM:", "RCPT TO:"],
        security_notes: "Port 25 often unencrypted. Ports 465/587 typically use TLS.",
    },
    ProtocolHint {
        name: "IMAP",
        description: "Internet Message Access Protocol - Email retrieval",
        common_ports: &[143, 993],
        indicators: &["* OK", "LOGIN ", "SELECT ", "FETCH "],
        security_notes: "Port 143 unencrypted. Port 993 uses TLS. Credentials may be visible.",
    },
    ProtocolHint {
        name: "MySQL",
        description: "MySQL Database Protocol",
        common_ports: &[3306],
        indicators: &[],
        security_notes: "Database traffic. Ensure TLS is enabled and queries don't leak sensitive data.",
    },
    ProtocolHint {
        name: "PostgreSQL",
        description: "PostgreSQL Database Protocol",
        common_ports: &[5432],
        indicators: &[],
        security_notes: "Database traffic. Ensure SSL is enabled in connection string.",
    },
    ProtocolHint {
        name: "Redis",
        description: "Redis In-Memory Data Store",
        common_ports: &[6379],
        indicators: &["*", "$", "+OK", "-ERR", "PING", "SET ", "GET "],
        security_notes: "Often runs without authentication! Ensure AUTH is enabled and network isolated.",
    },
    ProtocolHint {
        name: "MongoDB",
        description: "MongoDB NoSQL Database",
        common_ports: &[27017],
        indicators: &[],
        security_notes: "Ensure authentication is enabled. Many MongoDB instances are misconfigured.",
    },
    ProtocolHint {
        name: "RDP",
        description: "Remote Desktop Protocol - Windows remote access",
        common_ports: &[3389],
        indicators: &[],
        security_notes: "Target for brute-force attacks. Use VPN or restrict source IPs.",
    },
    ProtocolHint {
        name: "VNC",
        description: "Virtual Network Computing - Remote desktop",
        common_ports: &[5900, 5901],
        indicators: &["RFB "],
        security_notes: "Often weakly encrypted. Use SSH tunnel or VPN for secure access.",
    },
    ProtocolHint {
        name: "LDAP",
        description: "Lightweight Directory Access Protocol",
        common_ports: &[389, 636],
        indicators: &[],
        security_notes: "Port 389 unencrypted (credentials visible). Port 636 uses TLS.",
    },
    ProtocolHint {
        name: "NTP",
        description: "Network Time Protocol - Time synchronization",
        common_ports: &[123],
        indicators: &[],
        security_notes: "Can be abused for DDoS amplification. Restrict to trusted servers.",
    },
    ProtocolHint {
        name: "SNMP",
        description: "Simple Network Management Protocol",
        common_ports: &[161, 162],
        indicators: &[],
        security_notes: "v1/v2c send community strings in plaintext. Use SNMPv3 with encryption.",
    },
    ProtocolHint {
        name: "Telnet",
        description: "Telnet - Unencrypted remote access (legacy)",
        common_ports: &[23],
        indicators: &[], // Telnet negotiation uses non-ASCII bytes
        security_notes: "DANGER: Completely unencrypted. All data including passwords visible. Use SSH.",
    },
    ProtocolHint {
        name: "SIP",
        description: "Session Initiation Protocol - VoIP signaling",
        common_ports: &[5060, 5061],
        indicators: &["INVITE ", "SIP/2.0", "REGISTER "],
        security_notes: "VoIP traffic. Port 5060 unencrypted, 5061 uses TLS.",
    },
    ProtocolHint {
        name: "Kubernetes API",
        description: "Kubernetes API Server",
        common_ports: &[6443, 8443],
        indicators: &[],
        security_notes: "Sensitive! Unauthorized access = cluster compromise. Verify TLS and RBAC.",
    },
    ProtocolHint {
        name: "Docker",
        description: "Docker Daemon API",
        common_ports: &[2375, 2376],
        indicators: &[],
        security_notes: "Port 2375 unencrypted! Never expose. Port 2376 uses TLS.",
    },
    ProtocolHint {
        name: "Elasticsearch",
        description: "Elasticsearch Search Engine",
        common_ports: &[9200, 9300],
        indicators: &[],
        security_notes: "Often misconfigured without authentication. Ensure X-Pack security is enabled.",
    },
];

/// Identify traffic patterns in a packet
pub fn identify_traffic_pattern(
    src_port: Option<u16>,
    dst_port: Option<u16>,
    payload: &[u8],
    payload_text: Option<&str>,
) -> Option<String> {
    // First check by port
    for hint in PROTOCOL_HINTS {
        if let Some(port) = dst_port {
            if hint.common_ports.contains(&port) {
                return Some(hint.name.to_string());
            }
        }
        if let Some(port) = src_port {
            if hint.common_ports.contains(&port) {
                return Some(hint.name.to_string());
            }
        }
    }

    // Check by payload indicators
    if let Some(text) = payload_text {
        for hint in PROTOCOL_HINTS {
            for indicator in hint.indicators {
                if text.contains(indicator) {
                    return Some(hint.name.to_string());
                }
            }
        }
    }

    // Check binary indicators
    for hint in PROTOCOL_HINTS {
        for indicator in hint.indicators {
            let indicator_bytes = indicator.as_bytes();
            if payload.len() >= indicator_bytes.len()
                && &payload[..indicator_bytes.len()] == indicator_bytes
            {
                return Some(hint.name.to_string());
            }
        }
    }

    None
}

/// Get detailed help for a protocol
pub fn get_protocol_help(name: &str) -> Option<&'static ProtocolHint> {
    PROTOCOL_HINTS.iter().find(|h| h.name.eq_ignore_ascii_case(name))
}

/// Format all protocol hints for the help screen
pub fn format_help_text() -> String {
    let mut text = String::new();
    text.push_str("=== Traffic Pattern Help ===\n\n");

    for hint in PROTOCOL_HINTS {
        text.push_str(&format!("▸ {} (ports: {:?})\n", hint.name, hint.common_ports));
        text.push_str(&format!("  {}\n", hint.description));
        text.push_str(&format!("  ⚠ {}\n\n", hint.security_notes));
    }

    text.push_str("\n=== TCP Flag Reference ===\n\n");
    text.push_str("SYN       - Connection initiation request\n");
    text.push_str("SYN-ACK   - Connection acceptance\n");
    text.push_str("ACK       - Acknowledgment of received data\n");
    text.push_str("FIN       - Connection termination request\n");
    text.push_str("RST       - Connection reset (abrupt close)\n");
    text.push_str("PSH       - Push data immediately to application\n");
    text.push_str("URG       - Urgent data present\n\n");

    text.push_str("=== Common Patterns ===\n\n");
    text.push_str("Three-Way Handshake:\n");
    text.push_str("  1. Client → Server: SYN\n");
    text.push_str("  2. Server → Client: SYN-ACK\n");
    text.push_str("  3. Client → Server: ACK\n\n");

    text.push_str("Connection Close:\n");
    text.push_str("  1. Initiator: FIN-ACK\n");
    text.push_str("  2. Responder: ACK (then FIN-ACK)\n");
    text.push_str("  3. Initiator: ACK\n\n");

    text.push_str("Port Scan Indicators:\n");
    text.push_str("  - Many SYN packets to different ports\n");
    text.push_str("  - RST responses (closed ports)\n");
    text.push_str("  - No response (filtered ports)\n");

    text
}
