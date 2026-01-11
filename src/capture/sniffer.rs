use std::net::IpAddr;
use tokio::sync::mpsc;

use super::packet::{CapturedPacket, TcpFlags, TransportProtocol};
use super::protocol_hints::identify_traffic_pattern;

#[derive(Debug)]
pub enum SnifferCommand {
    Stop,
    SetFilter(String),
}

pub struct PacketSniffer;

impl PacketSniffer {
    pub async fn start(
        interface: Option<String>,
    ) -> (mpsc::UnboundedSender<SnifferCommand>, mpsc::UnboundedReceiver<CapturedPacket>) {
        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<SnifferCommand>();
        let (packet_tx, packet_rx) = mpsc::unbounded_channel::<CapturedPacket>();

        tokio::task::spawn_blocking(move || {
            Self::capture_loop(interface, &mut cmd_rx, &packet_tx);
        });

        (cmd_tx, packet_rx)
    }

    fn capture_loop(
        interface: Option<String>,
        cmd_rx: &mut mpsc::UnboundedReceiver<SnifferCommand>,
        packet_tx: &mpsc::UnboundedSender<CapturedPacket>,
    ) {
        // Get the default device or specified interface
        let device = if let Some(ref iface) = interface {
            pcap::Device::list()
                .unwrap_or_default()
                .into_iter()
                .find(|d| d.name == *iface)
                .unwrap_or_else(|| {
                    pcap::Device::lookup().ok().flatten().unwrap_or_else(|| {
                        pcap::Device {
                            name: "en0".to_string(),
                            desc: None,
                            addresses: vec![],
                            flags: pcap::DeviceFlags::empty(),
                        }
                    })
                })
        } else {
            match pcap::Device::lookup() {
                Ok(Some(device)) => device,
                Ok(None) => {
                    log::error!("No network device found");
                    return;
                }
                Err(e) => {
                    log::error!("Failed to lookup device: {}", e);
                    return;
                }
            }
        };

        log::info!("Starting capture on device: {}", device.name);

        // Open capture
        let mut cap = match pcap::Capture::from_device(device.clone()) {
            Ok(cap) => match cap
                .promisc(true)
                .snaplen(65535)
                .timeout(100)
                .open()
            {
                Ok(cap) => cap,
                Err(e) => {
                    log::error!("Failed to open capture: {}. Try running with sudo.", e);
                    return;
                }
            },
            Err(e) => {
                log::error!("Failed to create capture from device: {}", e);
                return;
            }
        };

        // Get the datalink type to know how to parse
        let datalink = cap.get_datalink();
        log::info!("Datalink type: {:?}", datalink);

        let mut packet_id = 0usize;
        let active = true;

        loop {
            // Check for commands (non-blocking)
            match cmd_rx.try_recv() {
                Ok(SnifferCommand::Stop) => {
                    log::info!("Sniffer stopped by command");
                    break;
                }
                Ok(SnifferCommand::SetFilter(new_filter)) => {
                    if !new_filter.is_empty() {
                        match cap.filter(&new_filter, true) {
                            Ok(_) => log::info!("Filter applied: {}", new_filter),
                            Err(e) => log::error!("Failed to apply filter: {}", e),
                        }
                    }
                }
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    log::info!("Sniffer command channel disconnected");
                    break;
                }
                Err(mpsc::error::TryRecvError::Empty) => {}
            }

            if !active {
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }

            // Capture next packet
            match cap.next_packet() {
                Ok(packet) => {
                    // Try to parse based on datalink type
                    let parsed = if datalink == pcap::Linktype::NULL || datalink == pcap::Linktype(12) {
                        // BSD loopback - 4 byte header
                        Self::parse_loopback_packet(packet_id, packet.data)
                    } else {
                        // Assume Ethernet
                        Self::parse_ethernet_packet(packet_id, packet.data)
                    };

                    if let Some(parsed) = parsed {
                        packet_id += 1;
                        if packet_tx.send(parsed).is_err() {
                            log::info!("Packet receiver disconnected");
                            break;
                        }
                    }
                }
                Err(pcap::Error::TimeoutExpired) => {
                    // Normal timeout, continue
                }
                Err(e) => {
                    log::error!("Capture error: {}", e);
                    break;
                }
            }
        }
    }

    fn parse_loopback_packet(id: usize, data: &[u8]) -> Option<CapturedPacket> {
        if data.len() < 4 {
            return None;
        }

        // BSD loopback header is 4 bytes containing the protocol family
        let af = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);

        // AF_INET = 2 on most systems
        if af != 2 {
            return None; // Not IPv4
        }

        Self::parse_ip_packet(id, &data[4..], None, None)
    }

    fn parse_ethernet_packet(id: usize, data: &[u8]) -> Option<CapturedPacket> {
        if data.len() < 14 {
            return None;
        }

        let eth_dst = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            data[0], data[1], data[2], data[3], data[4], data[5]
        );
        let eth_src = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            data[6], data[7], data[8], data[9], data[10], data[11]
        );
        let eth_type = u16::from_be_bytes([data[12], data[13]]);

        // Only handle IPv4 (0x0800) for now
        if eth_type != 0x0800 {
            return None;
        }

        Self::parse_ip_packet(id, &data[14..], Some(eth_src), Some(eth_dst))
    }

    fn parse_ip_packet(id: usize, ip_data: &[u8], eth_src: Option<String>, eth_dst: Option<String>) -> Option<CapturedPacket> {
        if ip_data.len() < 20 {
            return None;
        }

        let ip_version = (ip_data[0] >> 4) & 0x0F;
        let ip_header_len = ((ip_data[0] & 0x0F) * 4) as usize;
        let ip_protocol = ip_data[9];
        let ip_ttl = ip_data[8];

        let ip_src: IpAddr = std::net::Ipv4Addr::new(
            ip_data[12], ip_data[13], ip_data[14], ip_data[15]
        ).into();
        let ip_dst: IpAddr = std::net::Ipv4Addr::new(
            ip_data[16], ip_data[17], ip_data[18], ip_data[19]
        ).into();

        if ip_data.len() < ip_header_len {
            return None;
        }

        let transport_data = &ip_data[ip_header_len..];
        let transport_protocol = TransportProtocol::from_ip_protocol(ip_protocol);

        let (src_port, dst_port, tcp_flags, tcp_seq, tcp_ack, payload_offset) = match transport_protocol {
            TransportProtocol::Tcp if transport_data.len() >= 20 => {
                let src = u16::from_be_bytes([transport_data[0], transport_data[1]]);
                let dst = u16::from_be_bytes([transport_data[2], transport_data[3]]);
                let seq = u32::from_be_bytes([
                    transport_data[4], transport_data[5], transport_data[6], transport_data[7]
                ]);
                let ack = u32::from_be_bytes([
                    transport_data[8], transport_data[9], transport_data[10], transport_data[11]
                ]);
                let data_offset = ((transport_data[12] >> 4) * 4) as usize;
                let flags = TcpFlags::from_byte(transport_data[13]);
                (Some(src), Some(dst), Some(flags), Some(seq), Some(ack), data_offset)
            }
            TransportProtocol::Udp if transport_data.len() >= 8 => {
                let src = u16::from_be_bytes([transport_data[0], transport_data[1]]);
                let dst = u16::from_be_bytes([transport_data[2], transport_data[3]]);
                (Some(src), Some(dst), None, None, None, 8)
            }
            TransportProtocol::Icmp => {
                (None, None, None, None, None, 0)
            }
            _ => (None, None, None, None, None, 0),
        };

        let payload = if transport_data.len() > payload_offset {
            transport_data[payload_offset..].to_vec()
        } else {
            Vec::new()
        };

        let payload_text = if !payload.is_empty() {
            let text: String = payload
                .iter()
                .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
                .map(|&b| b as char)
                .collect();
            if text.len() > 10 {
                Some(text)
            } else {
                None
            }
        } else {
            None
        };

        let pattern_match = identify_traffic_pattern(
            src_port,
            dst_port,
            &payload,
            payload_text.as_deref(),
        );

        let service_hint = src_port
            .and_then(crate::network::connection::get_service_name)
            .or_else(|| dst_port.and_then(crate::network::connection::get_service_name))
            .map(String::from);

        let total_len = ip_data.len() + eth_src.as_ref().map(|_| 14).unwrap_or(4);

        Some(CapturedPacket {
            id,
            timestamp: chrono::Utc::now(),
            length: total_len,
            eth_src,
            eth_dst,
            eth_type: 0x0800,
            ip_version: Some(ip_version),
            ip_src: Some(ip_src),
            ip_dst: Some(ip_dst),
            ip_protocol: Some(ip_protocol),
            ip_ttl: Some(ip_ttl),
            transport_protocol,
            src_port,
            dst_port,
            tcp_flags,
            tcp_seq,
            tcp_ack,
            payload,
            payload_text,
            service_hint,
            pattern_match,
        })
    }
}
