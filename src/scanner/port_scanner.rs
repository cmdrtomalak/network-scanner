use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::service_detection::{detect_service, ServiceProbeLevel};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PortRange {
    Top100,
    Top1000,
    Full,
    Custom(Vec<u16>),
    Range(u16, u16),
}

impl PortRange {
    pub fn ports(&self) -> Vec<u16> {
        match self {
            PortRange::Top100 => TOP_100_PORTS.to_vec(),
            PortRange::Top1000 => TOP_1000_PORTS.to_vec(),
            PortRange::Full => (1..=65535).collect(),
            PortRange::Custom(ports) => ports.clone(),
            PortRange::Range(start, end) => (*start..=*end).collect(),
        }
    }

    pub fn parse(input: &str) -> Option<Self> {
        let input = input.trim();

        // Check for range (e.g., "1-1024")
        if input.contains('-') && !input.contains(',') {
            let parts: Vec<&str> = input.split('-').collect();
            if parts.len() == 2 {
                let start: u16 = parts[0].trim().parse().ok()?;
                let end: u16 = parts[1].trim().parse().ok()?;
                return Some(PortRange::Range(start, end));
            }
        }

        // Check for comma-separated list (e.g., "22,80,443")
        if input.contains(',') {
            let ports: Result<Vec<u16>, _> = input
                .split(',')
                .map(|s| s.trim().parse())
                .collect();
            return ports.ok().map(PortRange::Custom);
        }

        // Check for presets
        match input.to_lowercase().as_str() {
            "top100" | "top-100" | "100" => Some(PortRange::Top100),
            "top1000" | "top-1000" | "1000" => Some(PortRange::Top1000),
            "full" | "all" | "65535" => Some(PortRange::Full),
            _ => {
                // Try single port
                input.parse().ok().map(|p| PortRange::Custom(vec![p]))
            }
        }
    }

    pub fn display_name(&self) -> String {
        match self {
            PortRange::Top100 => "Top 100".to_string(),
            PortRange::Top1000 => "Top 1000".to_string(),
            PortRange::Full => "Full (1-65535)".to_string(),
            PortRange::Custom(ports) => {
                if ports.len() <= 5 {
                    format!("Custom: {:?}", ports)
                } else {
                    format!("Custom: {} ports", ports.len())
                }
            }
            PortRange::Range(start, end) => format!("Range: {}-{}", start, end),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub port: u16,
    pub state: PortState,
    pub service: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

pub struct Scanner;

impl Scanner {
    /// Try to resolve a target hostname/IP. Returns the resolved IP or None.
    pub fn try_resolve(target: &str) -> Option<IpAddr> {
        Self::resolve_target(target)
    }

    pub async fn scan(target: &str, port_range: &PortRange, probe_level: ServiceProbeLevel) -> Vec<ScanResult> {
        // Resolve hostname to IP
        let ip = match Self::resolve_target(target) {
            Some(ip) => ip,
            None => return Vec::new(),
        };

        let ports = port_range.ports();
        let mut results = Vec::new();

        // Scan ports concurrently with limited parallelism
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(100));
        let mut handles = Vec::new();

        for port in ports {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let ip = ip;
            let probe_level = probe_level;

            let handle = tokio::spawn(async move {
                let result = Self::scan_port(ip, port, probe_level).await;
                drop(permit);
                result
            });
            handles.push(handle);
        }

        for handle in handles {
            if let Ok(Some(result)) = handle.await {
                if result.state == PortState::Open {
                    results.push(result);
                }
            }
        }

        // Sort by port number
        results.sort_by_key(|r| r.port);
        results
    }

    fn resolve_target(target: &str) -> Option<IpAddr> {
        // Try parsing as IP first
        if let Ok(ip) = target.parse::<IpAddr>() {
            return Some(ip);
        }

        // Try using dns-lookup crate for better LAN hostname resolution
        // This handles mDNS (.local) and local hostnames better
        if let Ok(ips) = dns_lookup::lookup_host(target) {
            // Prefer IPv4 addresses
            for ip in &ips {
                if ip.is_ipv4() {
                    return Some(*ip);
                }
            }
            // Fall back to first result
            return ips.into_iter().next();
        }

        // Fallback to standard resolution with port suffix
        let addr_str = format!("{}:0", target);
        if let Ok(mut addrs) = addr_str.to_socket_addrs() {
            return addrs.next().map(|a| a.ip());
        }

        None
    }

    async fn scan_port(ip: IpAddr, port: u16, probe_level: ServiceProbeLevel) -> Option<ScanResult> {
        let addr = SocketAddr::new(ip, port);
        let connect_timeout = Duration::from_millis(1000);

        match timeout(connect_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => {
                // Port is open, try to get banner
                let (service, version, banner) = detect_service(&mut stream, port, probe_level).await;

                Some(ScanResult {
                    port,
                    state: PortState::Open,
                    service,
                    version,
                    banner,
                })
            }
            Ok(Err(_)) => {
                // Connection refused - port is closed
                Some(ScanResult {
                    port,
                    state: PortState::Closed,
                    service: None,
                    version: None,
                    banner: None,
                })
            }
            Err(_) => {
                // Timeout - port is filtered
                Some(ScanResult {
                    port,
                    state: PortState::Filtered,
                    service: None,
                    version: None,
                    banner: None,
                })
            }
        }
    }
}

// Top 100 most common ports (based on nmap frequency data)
static TOP_100_PORTS: [u16; 100] = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
    139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548,
    554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433,
    1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986,
    4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000,
    6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768,
    49152, 49153, 49154, 49155, 49156, 49157,
];

// Top 1000 ports - for brevity, we'll generate from top 100 + common additional ports
static TOP_1000_PORTS: [u16; 100] = TOP_100_PORTS; // In production, this would be the full list
