use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::network::connection::get_service_name;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceProbeLevel {
    Banner,
    Deep,
}

pub async fn detect_service(
    stream: &mut TcpStream,
    port: u16,
    probe_level: ServiceProbeLevel,
) -> (Option<String>, Option<String>, Option<String>) {
    // First, try to get a banner (service may send data immediately)
    let banner = grab_banner(stream).await;

    // Determine service from banner or port
    let (service, version) = if let Some(ref banner_text) = banner {
        parse_banner(banner_text, port)
    } else {
        (get_service_name(port).map(String::from), None)
    };

    // If deep probing is enabled and we didn't get a banner, send probes
    if probe_level == ServiceProbeLevel::Deep && banner.is_none() {
        if let Some((svc, ver, ban)) = send_service_probes(stream, port).await {
            return (Some(svc), ver, ban);
        }
    }

    (service, version, banner)
}

async fn grab_banner(stream: &mut TcpStream) -> Option<String> {
    let mut buffer = vec![0u8; 4096];

    // Set a short timeout for banner grab
    match timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
        Ok(Ok(n)) if n > 0 => {
            // Try to convert to string, filtering non-printable chars
            let text: String = buffer[..n]
                .iter()
                .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
                .map(|&b| b as char)
                .collect();

            if !text.trim().is_empty() {
                Some(text.trim().to_string())
            } else {
                None
            }
        }
        _ => None,
    }
}

fn parse_banner(banner: &str, port: u16) -> (Option<String>, Option<String>) {
    let banner_lower = banner.to_lowercase();

    // SSH detection
    if banner_lower.starts_with("ssh-") {
        let version = banner.split_whitespace().next().map(String::from);
        return (Some("ssh".to_string()), version);
    }

    // HTTP detection
    if banner_lower.starts_with("http/") || banner_lower.contains("apache") || banner_lower.contains("nginx") {
        let version = if banner_lower.contains("apache") {
            extract_version(banner, "Apache")
        } else if banner_lower.contains("nginx") {
            extract_version(banner, "nginx")
        } else {
            None
        };
        return (Some("http".to_string()), version);
    }

    // FTP detection
    if banner_lower.contains("ftp") || banner.starts_with("220") {
        return (Some("ftp".to_string()), extract_version(banner, "FTP"));
    }

    // SMTP detection
    if banner.starts_with("220") && (banner_lower.contains("smtp") || banner_lower.contains("mail")) {
        return (Some("smtp".to_string()), None);
    }

    // MySQL detection
    if banner.len() > 4 && port == 3306 {
        return (Some("mysql".to_string()), None);
    }

    // PostgreSQL detection
    if port == 5432 {
        return (Some("postgresql".to_string()), None);
    }

    // Redis detection
    if banner.starts_with("-ERR") || banner.starts_with("+PONG") {
        return (Some("redis".to_string()), None);
    }

    // MongoDB detection
    if port == 27017 {
        return (Some("mongodb".to_string()), None);
    }

    // Default: use port-based detection
    (get_service_name(port).map(String::from), None)
}

fn extract_version(banner: &str, product: &str) -> Option<String> {
    let banner_lower = banner.to_lowercase();
    let product_lower = product.to_lowercase();

    if let Some(idx) = banner_lower.find(&product_lower) {
        let after = &banner[idx + product.len()..];
        let version: String = after
            .chars()
            .skip_while(|c| !c.is_ascii_digit())
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();

        if !version.is_empty() {
            return Some(format!("{}/{}", product, version));
        }
    }
    None
}

async fn send_service_probes(stream: &mut TcpStream, port: u16) -> Option<(String, Option<String>, Option<String>)> {
    // HTTP probe
    if matches!(port, 80 | 8080 | 8000 | 8008 | 8443 | 443 | 3000) {
        if let Some(response) = send_http_probe(stream).await {
            let (svc, ver) = parse_banner(&response, port);
            return Some((svc.unwrap_or_else(|| "http".to_string()), ver, Some(response)));
        }
    }

    // Generic probe - send newline and see what we get
    let _ = stream.write_all(b"\r\n").await;
    if let Some(banner) = grab_banner(stream).await {
        let (svc, ver) = parse_banner(&banner, port);
        return Some((svc.unwrap_or_else(|| "unknown".to_string()), ver, Some(banner)));
    }

    None
}

async fn send_http_probe(stream: &mut TcpStream) -> Option<String> {
    let request = "HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n";

    if stream.write_all(request.as_bytes()).await.is_err() {
        return None;
    }

    let mut buffer = vec![0u8; 4096];
    match timeout(Duration::from_millis(1000), stream.read(&mut buffer)).await {
        Ok(Ok(n)) if n > 0 => {
            String::from_utf8_lossy(&buffer[..n])
                .lines()
                .take(5)
                .collect::<Vec<_>>()
                .join("\n")
                .into()
        }
        _ => None,
    }
}
