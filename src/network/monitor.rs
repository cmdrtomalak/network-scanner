use std::net::IpAddr;
use std::process::Command;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use super::Connection;

pub struct ConnectionMonitor {
    connections: Arc<RwLock<Vec<Connection>>>,
}

impl ConnectionMonitor {
    pub fn new(refresh_rate_ms: u64) -> Self {
        let connections = Arc::new(RwLock::new(Vec::new()));
        let connections_clone = connections.clone();

        // Spawn background thread to refresh connections
        std::thread::spawn(move || {
            loop {
                let new_connections = Self::fetch_connections();
                if let Ok(mut conns) = connections_clone.write() {
                    *conns = new_connections;
                }
                std::thread::sleep(Duration::from_millis(refresh_rate_ms));
            }
        });

        Self { connections }
    }

    pub fn get_connections(&self) -> Vec<Connection> {
        self.connections.read().map(|c| c.clone()).unwrap_or_default()
    }

    #[cfg(target_os = "macos")]
    fn fetch_connections() -> Vec<Connection> {
        let mut connections = Vec::new();

        // Use netstat on macOS
        if let Ok(output) = Command::new("netstat").args(["-anv", "-p", "tcp"]).output() {
            if let Ok(stdout) = String::from_utf8(output.stdout) {
                connections.extend(Self::parse_netstat_output(&stdout, "tcp"));
            }
        }

        if let Ok(output) = Command::new("netstat").args(["-anv", "-p", "udp"]).output() {
            if let Ok(stdout) = String::from_utf8(output.stdout) {
                connections.extend(Self::parse_netstat_output(&stdout, "udp"));
            }
        }

        // Try to get process names using lsof
        Self::enrich_with_process_info(&mut connections);

        connections
    }

    #[cfg(target_os = "linux")]
    fn fetch_connections() -> Vec<Connection> {
        let mut connections = Vec::new();

        // Use ss on Linux (faster than netstat)
        if let Ok(output) = Command::new("ss").args(["-tunap"]).output() {
            if let Ok(stdout) = String::from_utf8(output.stdout) {
                connections.extend(Self::parse_ss_output(&stdout));
            }
        }

        connections
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    fn fetch_connections() -> Vec<Connection> {
        Vec::new()
    }

    #[cfg(target_os = "macos")]
    fn parse_netstat_output(output: &str, protocol: &str) -> Vec<Connection> {
        let mut connections = Vec::new();

        for line in output.lines().skip(2) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 6 {
                continue;
            }

            // Parse local address
            let (local_addr, local_port) = match Self::parse_address(parts[3]) {
                Some(v) => v,
                None => continue,
            };

            // Parse remote address
            let (remote_addr, remote_port) = Self::parse_address(parts[4])
                .map(|(a, p)| (Some(a), Some(p)))
                .unwrap_or((None, None));

            // Get state (for TCP)
            let state = if protocol == "tcp" && parts.len() > 5 {
                parts[5].to_string()
            } else {
                "".to_string()
            };

            // Determine if inbound based on well-known ports
            let is_inbound = local_port < 1024 || (remote_port.map(|p| p >= 1024).unwrap_or(false) && local_port < remote_port.unwrap_or(0));

            connections.push(Connection {
                protocol: protocol.to_uppercase(),
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                state,
                pid: None,
                gid: None,
                process_name: None,
                is_inbound,
            });
        }

        connections
    }

    #[cfg(target_os = "linux")]
    fn parse_ss_output(output: &str) -> Vec<Connection> {
        let mut connections = Vec::new();

        for line in output.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 5 {
                continue;
            }

            let protocol = parts[0].to_uppercase();
            let state = parts[1].to_string();

            // Parse local address (format: addr:port or [addr]:port)
            let (local_addr, local_port) = match Self::parse_address(parts[4]) {
                Some(v) => v,
                None => continue,
            };

            // Parse remote address
            let (remote_addr, remote_port) = if parts.len() > 5 {
                Self::parse_address(parts[5])
                    .map(|(a, p)| (Some(a), Some(p)))
                    .unwrap_or((None, None))
            } else {
                (None, None)
            };

            // Extract PID and process name if available
            let (pid, process_name) = if parts.len() > 6 {
                Self::parse_process_info(parts[6])
            } else {
                (None, None)
            };

            let gid = pid.and_then(Self::get_gid_from_pid);

            let is_inbound = local_port < 1024 || (remote_port.map(|p| p >= 1024).unwrap_or(false) && local_port < remote_port.unwrap_or(0));

            connections.push(Connection {
                protocol,
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                state,
                pid,
                gid,
                process_name,
                is_inbound,
            });
        }

        connections
    }

    fn get_gid_from_pid(pid: u32) -> Option<u32> {
        #[cfg(target_os = "linux")]
        {
            use std::io::Read;
            let path = format!("/proc/{}/status", pid);
            if let Ok(mut file) = std::fs::File::open(&path) {
                let mut contents = String::new();
                if file.read_to_string(&mut contents).is_ok() {
                    for line in contents.lines() {
                        if line.starts_with("Gid:") {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() >= 3 {
                                return parts[2].parse().ok(); // Real, Effective, Saved, FS
                            }
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
             if let Ok(output) = Command::new("ps")
                .args(["-p", &pid.to_string(), "-o", "gid="])
                .output()
            {
                if let Ok(s) = String::from_utf8(output.stdout) {
                    return s.trim().parse().ok();
                }
            }
        }

        None
    }

    fn parse_address(addr_str: &str) -> Option<(IpAddr, u16)> {
        // Handle IPv6 format [addr]:port
        if addr_str.starts_with('[') {
            if let Some(bracket_end) = addr_str.find(']') {
                let addr = &addr_str[1..bracket_end];
                let port_part = &addr_str[bracket_end + 1..];
                if port_part.starts_with(':') {
                    let port: u16 = port_part[1..].parse().ok()?;
                    let ip = IpAddr::from_str(addr).ok()?;
                    return Some((ip, port));
                }
            }
            return None;
        }

        // Handle IPv4 format addr.port or addr:port
        // macOS uses addr.port format, Linux uses addr:port
        let last_sep = addr_str.rfind(|c| c == '.' || c == ':');
        if let Some(sep_idx) = last_sep {
            let (addr_part, port_part) = addr_str.split_at(sep_idx);
            let port: u16 = port_part[1..].parse().ok()?;

            // Handle wildcard addresses
            let addr_str = if addr_part == "*" || addr_part.is_empty() {
                "0.0.0.0"
            } else {
                addr_part
            };

            let ip = IpAddr::from_str(addr_str).ok()?;
            return Some((ip, port));
        }

        None
    }

    #[cfg(target_os = "linux")]
    fn parse_process_info(info: &str) -> (Option<u32>, Option<String>) {
        // Format: users:(("process",pid=123,fd=4))
        if let Some(start) = info.find("pid=") {
            let rest = &info[start + 4..];
            if let Some(end) = rest.find(',') {
                if let Ok(pid) = rest[..end].parse() {
                    // Try to extract process name
                    if let Some(name_start) = info.find("((\"") {
                        if let Some(name_end) = info[name_start + 3..].find('"') {
                            let name = info[name_start + 3..name_start + 3 + name_end].to_string();
                            return (Some(pid), Some(name));
                        }
                    }
                    return (Some(pid), None);
                }
            }
        }
        (None, None)
    }

    #[cfg(target_os = "macos")]
    fn enrich_with_process_info(connections: &mut [Connection]) {
        // Use lsof to get process information
        if let Ok(output) = Command::new("lsof").args(["-i", "-n", "-P"]).output() {
            if let Ok(stdout) = String::from_utf8(output.stdout) {
                for line in stdout.lines().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() < 9 {
                        continue;
                    }

                    let process_name = parts[0].to_string();
                    let pid: Option<u32> = parts[1].parse().ok();

                    // Parse the address from lsof (format: host:port or host:port->remote:port)
                    let addr_info = parts[8];
                    if let Some((local, _)) = addr_info.split_once("->") {
                        if let Some((_, port_str)) = local.rsplit_once(':') {
                            if let Ok(port) = port_str.parse::<u16>() {
                                for conn in connections.iter_mut() {
                                    if conn.local_port == port && conn.process_name.is_none() {
                                        conn.process_name = Some(process_name.clone());
                                        conn.pid = pid;
                                        if let Some(p) = pid {
                                            conn.gid = Self::get_gid_from_pid(p);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
