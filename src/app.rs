use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::mpsc;

use crate::capture::{CapturedPacket, PacketSniffer, SnifferCommand};
use crate::network::{Connection, ConnectionMonitor};
use crate::scanner::{PortRange, ScanResult, Scanner, ServiceProbeLevel};
use crate::ui::theme::ThemeName;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tab {
    #[default]
    Dashboard,
    PortScanner,
    PacketSniffer,
}

impl Tab {
    pub fn next(self) -> Self {
        match self {
            Tab::Dashboard => Tab::PortScanner,
            Tab::PortScanner => Tab::PacketSniffer,
            Tab::PacketSniffer => Tab::Dashboard,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Tab::Dashboard => Tab::PacketSniffer,
            Tab::PortScanner => Tab::Dashboard,
            Tab::PacketSniffer => Tab::PortScanner,
        }
    }

    pub fn title(&self) -> &'static str {
        match self {
            Tab::Dashboard => "Machine Info",
            Tab::PortScanner => "Port Scanner",
            Tab::PacketSniffer => "Packet Sniffer",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DashboardPanel {
    #[default]
    OpenPorts,
    Inbound,
    Outbound,
}

impl DashboardPanel {
    pub fn next(self) -> Self {
        match self {
            DashboardPanel::OpenPorts => DashboardPanel::Inbound,
            DashboardPanel::Inbound => DashboardPanel::Outbound,
            DashboardPanel::Outbound => DashboardPanel::OpenPorts,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InputMode {
    #[default]
    Normal,
    Editing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScannerFocus {
    #[default]
    Target,
    Ports,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanHistory {
    pub target: String,
    pub port_range: PortRange,
    pub results: Vec<ScanResult>,
}

pub struct App {
    pub current_tab: Tab,
    pub should_quit: bool,
    pub interface: Option<String>,
    pub refresh_rate_ms: u64,

    // Dashboard state
    pub dashboard_panel: DashboardPanel,
    pub open_ports: Vec<Connection>,
    pub inbound_connections: Vec<Connection>,
    pub outbound_connections: Vec<Connection>,
    pub dashboard_scroll: [usize; 3], // scroll position for each panel
    pub connection_monitor: Option<ConnectionMonitor>,

    // Port Scanner state
    pub scanner_input: String,
    pub scanner_input_mode: InputMode,
    pub scanner_focus: ScannerFocus,
    pub scanner_port_input: String,
    pub scanner_port_range: PortRange,
    pub scanner_probe_level: ServiceProbeLevel,
    pub scanner_results: Vec<ScanResult>,
    pub scanner_scroll: usize,
    pub scanner_running: bool,
    pub scanner_history: Vec<ScanHistory>,
    pub scanner_selected_preset: usize,

    // Packet Sniffer state
    pub sniffer_active: bool,
    pub sniffer_packets: Vec<CapturedPacket>,
    pub sniffer_scroll: usize,
    pub sniffer_expanded: HashMap<usize, bool>,
    pub sniffer_show_hex: bool,
    pub sniffer_filter: String,
    pub sniffer_filter_mode: InputMode,
    pub sniffer_show_help: bool,
    pub sniffer_cmd_tx: Option<mpsc::UnboundedSender<SnifferCommand>>,
    pub sniffer_packet_rx: Option<mpsc::UnboundedReceiver<CapturedPacket>>,

    // UI state
    pub status_message: Option<String>,
    pub status_message_time: Option<std::time::Instant>,
    pub theme: ThemeName,
}

impl App {
    pub fn new(interface: Option<String>, refresh_rate_ms: u64) -> Self {
        Self {
            current_tab: Tab::default(),
            should_quit: false,
            interface,
            refresh_rate_ms,

            // Dashboard
            dashboard_panel: DashboardPanel::default(),
            open_ports: Vec::new(),
            inbound_connections: Vec::new(),
            outbound_connections: Vec::new(),
            dashboard_scroll: [0; 3],
            connection_monitor: None,

            // Port Scanner
            scanner_input: String::new(),
            scanner_input_mode: InputMode::Normal,
            scanner_focus: ScannerFocus::Target,
            scanner_port_input: String::new(),
            scanner_port_range: PortRange::Top100,
            scanner_probe_level: ServiceProbeLevel::Banner,
            scanner_results: Vec::new(),
            scanner_scroll: 0,
            scanner_running: false,
            scanner_history: Vec::new(),
            scanner_selected_preset: 0,

            // Packet Sniffer
            sniffer_active: false,
            sniffer_packets: Vec::new(),
            sniffer_scroll: 0,
            sniffer_expanded: HashMap::new(),
            sniffer_show_hex: false,
            sniffer_filter: String::new(),
            sniffer_filter_mode: InputMode::Normal,
            sniffer_show_help: false,
            sniffer_cmd_tx: None,
            sniffer_packet_rx: None,

            // UI
            status_message: None,
            status_message_time: None,
            theme: ThemeName::default(),
        }
    }

    pub async fn start_background_tasks(&mut self) {
        // Start connection monitor
        self.connection_monitor = Some(ConnectionMonitor::new(self.refresh_rate_ms));
    }

    pub async fn on_tick(&mut self) {
        // Update connections from monitor
        if let Some(monitor) = &self.connection_monitor {
            let connections = monitor.get_connections();
            self.open_ports = connections
                .iter()
                .filter(|c| c.state == "LISTEN")
                .cloned()
                .collect();
            self.inbound_connections = connections
                .iter()
                .filter(|c| c.state == "ESTABLISHED" && c.is_inbound)
                .cloned()
                .collect();
            self.outbound_connections = connections
                .iter()
                .filter(|c| c.state == "ESTABLISHED" && !c.is_inbound)
                .cloned()
                .collect();
        }

        // Poll for captured packets
        if let Some(rx) = &mut self.sniffer_packet_rx {
            // Drain all available packets (non-blocking)
            while let Ok(packet) = rx.try_recv() {
                self.sniffer_packets.push(packet);
                // Limit to last 10000 packets to avoid memory issues
                if self.sniffer_packets.len() > 10000 {
                    self.sniffer_packets.remove(0);
                }
            }
        }

        // Auto-dismiss status message after 4 seconds
        if let Some(time) = self.status_message_time {
            if time.elapsed() >= std::time::Duration::from_secs(4) {
                self.status_message = None;
                self.status_message_time = None;
            }
        }
    }

    /// Set a status message that will auto-dismiss after 4 seconds
    pub fn set_status(&mut self, message: String) {
        self.status_message = Some(message);
        self.status_message_time = Some(std::time::Instant::now());
    }

    /// Clear the status message immediately
    pub fn clear_status(&mut self) {
        self.status_message = None;
        self.status_message_time = None;
    }

    pub async fn handle_key(&mut self, key: KeyEvent) -> bool {
        // Global shortcuts
        match key.code {
            KeyCode::Char('q') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.should_quit = true;
                return true;
            }
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.should_quit = true;
                return true;
            }
            // ESC or Enter dismisses status message if present
            KeyCode::Esc | KeyCode::Enter if self.status_message.is_some() => {
                self.clear_status();
                return false;
            }
            // 't' cycles through themes (global shortcut)
            KeyCode::Char('t') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.theme = self.theme.next();
                self.set_status(format!("Theme: {}", self.theme.name()));
                return false;
            }
            _ => {}
        }

        // Handle based on input mode
        match self.current_tab {
            Tab::Dashboard => self.handle_dashboard_key(key).await,
            Tab::PortScanner => self.handle_scanner_key(key).await,
            Tab::PacketSniffer => self.handle_sniffer_key(key).await,
        }

        false
    }

    async fn handle_dashboard_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Tab => self.current_tab = self.current_tab.next(),
            KeyCode::BackTab => self.current_tab = self.current_tab.prev(),
            KeyCode::Left | KeyCode::Char('h') => {
                self.dashboard_panel = match self.dashboard_panel {
                    DashboardPanel::OpenPorts => DashboardPanel::Outbound,
                    DashboardPanel::Inbound => DashboardPanel::OpenPorts,
                    DashboardPanel::Outbound => DashboardPanel::Inbound,
                };
            }
            KeyCode::Right | KeyCode::Char('l') => {
                self.dashboard_panel = self.dashboard_panel.next();
            }
            KeyCode::Up | KeyCode::Char('k') => {
                let idx = self.dashboard_panel as usize;
                if self.dashboard_scroll[idx] > 0 {
                    self.dashboard_scroll[idx] -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let idx = self.dashboard_panel as usize;
                let max = match self.dashboard_panel {
                    DashboardPanel::OpenPorts => self.open_ports.len(),
                    DashboardPanel::Inbound => self.inbound_connections.len(),
                    DashboardPanel::Outbound => self.outbound_connections.len(),
                };
                if self.dashboard_scroll[idx] < max.saturating_sub(1) {
                    self.dashboard_scroll[idx] += 1;
                }
            }
            KeyCode::Char('e') => {
                self.export_dashboard().await;
            }
            _ => {}
        }
    }

    async fn handle_scanner_key(&mut self, key: KeyEvent) {
        match self.scanner_input_mode {
            InputMode::Normal => match key.code {
                KeyCode::Tab => self.current_tab = self.current_tab.next(),
                KeyCode::BackTab => self.current_tab = self.current_tab.prev(),
                KeyCode::Char('i') | KeyCode::Enter => {
                    self.scanner_input_mode = InputMode::Editing;
                }
                KeyCode::Char('o') => {
                    // Switch focus to ports input and enter editing mode
                    self.scanner_focus = ScannerFocus::Ports;
                    self.scanner_input_mode = InputMode::Editing;
                }
                KeyCode::Char('s') => {
                    self.start_scan().await;
                }
                KeyCode::Char('r') => {
                    self.rerun_last_scan().await;
                }
                KeyCode::Char('p') => {
                    // Cycle through presets: Top100 -> Top1000 -> Full -> Custom -> Top100
                    self.scanner_selected_preset = (self.scanner_selected_preset + 1) % 4;
                    self.scanner_port_range = match self.scanner_selected_preset {
                        0 => PortRange::Top100,
                        1 => PortRange::Top1000,
                        2 => PortRange::Full,
                        3 => {
                            // Custom - use existing port_input or default
                            if let Some(range) = PortRange::parse(&self.scanner_port_input) {
                                range
                            } else {
                                PortRange::Custom(vec![22, 80, 443])
                            }
                        }
                        _ => PortRange::Top100,
                    };
                }
                KeyCode::Char('d') => {
                    self.scanner_probe_level = match self.scanner_probe_level {
                        ServiceProbeLevel::Banner => ServiceProbeLevel::Deep,
                        ServiceProbeLevel::Deep => ServiceProbeLevel::Banner,
                    };
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    if self.scanner_scroll > 0 {
                        self.scanner_scroll -= 1;
                    }
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if self.scanner_scroll < self.scanner_results.len().saturating_sub(1) {
                        self.scanner_scroll += 1;
                    }
                }
                KeyCode::Char('e') => {
                    self.export_scan_results().await;
                }
                _ => {}
            },
            InputMode::Editing => match key.code {
                KeyCode::Enter => {
                    self.scanner_input_mode = InputMode::Normal;
                    if self.scanner_focus == ScannerFocus::Ports {
                        // Parse custom port range
                        if let Some(range) = PortRange::parse(&self.scanner_port_input) {
                            self.scanner_port_range = range;
                            self.scanner_selected_preset = 3; // Custom
                        } else if !self.scanner_port_input.is_empty() {
                            self.set_status("Invalid port format. Use: 22,80,443 or 1-1024".to_string());
                        }
                        self.scanner_focus = ScannerFocus::Target;
                    } else {
                        self.start_scan().await;
                    }
                }
                KeyCode::Esc => {
                    self.scanner_input_mode = InputMode::Normal;
                    self.scanner_focus = ScannerFocus::Target;
                }
                KeyCode::Tab => {
                    // Switch between target and ports while editing
                    self.scanner_focus = match self.scanner_focus {
                        ScannerFocus::Target => ScannerFocus::Ports,
                        ScannerFocus::Ports => ScannerFocus::Target,
                    };
                }
                KeyCode::Char(c) => {
                    match self.scanner_focus {
                        ScannerFocus::Target => self.scanner_input.push(c),
                        ScannerFocus::Ports => self.scanner_port_input.push(c),
                    }
                }
                KeyCode::Backspace => {
                    match self.scanner_focus {
                        ScannerFocus::Target => { self.scanner_input.pop(); }
                        ScannerFocus::Ports => { self.scanner_port_input.pop(); }
                    }
                }
                _ => {}
            },
        }
    }

    async fn handle_sniffer_key(&mut self, key: KeyEvent) {
        if self.sniffer_show_help {
            if key.code == KeyCode::Esc || key.code == KeyCode::Char('?') {
                self.sniffer_show_help = false;
            }
            return;
        }

        match self.sniffer_filter_mode {
            InputMode::Normal => match key.code {
                KeyCode::Tab => self.current_tab = self.current_tab.next(),
                KeyCode::BackTab => self.current_tab = self.current_tab.prev(),
                KeyCode::Char(' ') => {
                    self.toggle_sniffer().await;
                }
                KeyCode::Char('f') | KeyCode::Char('/') => {
                    self.sniffer_filter_mode = InputMode::Editing;
                }
                KeyCode::Char('h') => {
                    self.sniffer_show_hex = !self.sniffer_show_hex;
                }
                KeyCode::Char('?') => {
                    self.sniffer_show_help = true;
                }
                KeyCode::Char('c') => {
                    self.sniffer_packets.clear();
                    self.sniffer_expanded.clear();
                    self.sniffer_scroll = 0;
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    if self.sniffer_scroll > 0 {
                        self.sniffer_scroll -= 1;
                    }
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    let filtered_count = self.filtered_packets().len();
                    if self.sniffer_scroll < filtered_count.saturating_sub(1) {
                        self.sniffer_scroll += 1;
                    }
                }
                KeyCode::PageUp => {
                    self.sniffer_scroll = self.sniffer_scroll.saturating_sub(20);
                }
                KeyCode::PageDown => {
                    let filtered_count = self.filtered_packets().len();
                    self.sniffer_scroll = (self.sniffer_scroll + 20).min(filtered_count.saturating_sub(1));
                }
                KeyCode::Home => {
                    self.sniffer_scroll = 0;
                }
                KeyCode::End => {
                    let filtered_count = self.filtered_packets().len();
                    self.sniffer_scroll = filtered_count.saturating_sub(1);
                }
                KeyCode::Enter => {
                    // Get the original packet index from the filtered list
                    let filtered = self.filtered_packets();
                    if let Some((original_idx, _)) = filtered.get(self.sniffer_scroll) {
                        let expanded = self.sniffer_expanded.entry(*original_idx).or_insert(false);
                        *expanded = !*expanded;
                    }
                }
                KeyCode::Char('e') => {
                    self.export_packets().await;
                }
                _ => {}
            },
            InputMode::Editing => match key.code {
                KeyCode::Enter | KeyCode::Esc => {
                    self.sniffer_filter_mode = InputMode::Normal;
                    self.apply_sniffer_filter().await;
                }
                KeyCode::Char(c) => {
                    self.sniffer_filter.push(c);
                }
                KeyCode::Backspace => {
                    self.sniffer_filter.pop();
                }
                _ => {}
            },
        }
    }

    pub fn handle_mouse(&mut self, _mouse: MouseEvent) {
        // Mouse handling can be added later
    }

    async fn start_scan(&mut self) {
        if self.scanner_input.is_empty() || self.scanner_running {
            return;
        }

        let target = self.scanner_input.clone();

        // Check if target can be resolved first
        let resolved_ip = match Scanner::try_resolve(&target) {
            Some(ip) => ip,
            None => {
                self.set_status(format!(
                    "Could not resolve '{}' - check hostname or use IP address",
                    target
                ));
                return;
            }
        };

        self.scanner_running = true;
        self.scanner_results.clear();
        self.set_status(format!("Scanning {} ({})...", target, resolved_ip));

        let port_range = self.scanner_port_range.clone();
        let probe_level = self.scanner_probe_level;

        // Run scan in background
        let results = Scanner::scan(&target, &port_range, probe_level).await;

        self.scanner_results = results.clone();
        self.scanner_running = false;
        self.set_status(format!(
            "Scan complete: {} open ports found",
            results.len()
        ));

        // Save to history
        self.scanner_history.push(ScanHistory {
            target,
            port_range,
            results,
        });
    }

    async fn rerun_last_scan(&mut self) {
        if let Some(last) = self.scanner_history.last().cloned() {
            self.scanner_input = last.target;
            self.scanner_port_range = last.port_range;
            self.start_scan().await;
        }
    }

    async fn toggle_sniffer(&mut self) {
        if self.sniffer_active {
            // Stop sniffer
            if let Some(tx) = &self.sniffer_cmd_tx {
                let _ = tx.send(SnifferCommand::Stop);
            }
            self.sniffer_active = false;
            self.sniffer_cmd_tx = None;
            self.sniffer_packet_rx = None;
            self.set_status("Packet capture stopped".to_string());
        } else {
            // Start sniffer
            let interface = self.interface.clone();
            let (cmd_tx, packet_rx) = PacketSniffer::start(interface).await;
            self.sniffer_cmd_tx = Some(cmd_tx);
            self.sniffer_packet_rx = Some(packet_rx);
            self.sniffer_active = true;
            self.set_status("Packet capture started - packets will appear below".to_string());
        }
    }

    async fn apply_sniffer_filter(&mut self) {
        // The filter is applied both to BPF (for new packets) and display (for existing)
        if let Some(tx) = &self.sniffer_cmd_tx {
            let _ = tx.send(SnifferCommand::SetFilter(self.sniffer_filter.clone()));
        }
    }

    /// Get packets filtered by the current filter string
    /// Supports BPF-like syntax: 'port 80', 'host 192.168.1.1', 'tcp', 'udp'
    /// Also supports simple text matching as fallback
    pub fn filtered_packets(&self) -> Vec<(usize, &CapturedPacket)> {
        if self.sniffer_filter.is_empty() {
            return self.sniffer_packets.iter().enumerate().collect();
        }

        let filter = self.sniffer_filter.trim().to_lowercase();

        self.sniffer_packets
            .iter()
            .enumerate()
            .filter(|(_, packet)| self.packet_matches_filter(packet, &filter))
            .collect()
    }

    /// Check if a packet matches the filter expression
    fn packet_matches_filter(&self, packet: &CapturedPacket, filter: &str) -> bool {
        // Parse BPF-like syntax
        let parts: Vec<&str> = filter.split_whitespace().collect();

        match parts.as_slice() {
            // "port 80" - matches src or dst port
            ["port", port_str] => {
                if let Ok(port) = port_str.parse::<u16>() {
                    return packet.src_port == Some(port) || packet.dst_port == Some(port);
                }
                false
            }
            // "src port 80" - matches source port only
            ["src", "port", port_str] => {
                if let Ok(port) = port_str.parse::<u16>() {
                    return packet.src_port == Some(port);
                }
                false
            }
            // "dst port 80" - matches destination port only
            ["dst", "port", port_str] => {
                if let Ok(port) = port_str.parse::<u16>() {
                    return packet.dst_port == Some(port);
                }
                false
            }
            // "host 192.168.1.1" - matches src or dst IP
            ["host", ip_str] => {
                if let Some(ref src_ip) = packet.ip_src {
                    if src_ip.to_string() == *ip_str || src_ip.to_string().starts_with(ip_str) {
                        return true;
                    }
                }
                if let Some(ref dst_ip) = packet.ip_dst {
                    if dst_ip.to_string() == *ip_str || dst_ip.to_string().starts_with(ip_str) {
                        return true;
                    }
                }
                false
            }
            // "src host 192.168.1.1" - matches source IP only
            ["src", "host", ip_str] | ["src", ip_str] => {
                if let Some(ref src_ip) = packet.ip_src {
                    return src_ip.to_string() == *ip_str || src_ip.to_string().starts_with(ip_str);
                }
                false
            }
            // "dst host 192.168.1.1" - matches destination IP only
            ["dst", "host", ip_str] | ["dst", ip_str] => {
                if let Some(ref dst_ip) = packet.ip_dst {
                    return dst_ip.to_string() == *ip_str || dst_ip.to_string().starts_with(ip_str);
                }
                false
            }
            // "net 192.168.1" - matches network prefix on src or dst
            ["net", net_str] => {
                if let Some(ref src_ip) = packet.ip_src {
                    if src_ip.to_string().starts_with(net_str) {
                        return true;
                    }
                }
                if let Some(ref dst_ip) = packet.ip_dst {
                    if dst_ip.to_string().starts_with(net_str) {
                        return true;
                    }
                }
                false
            }
            // Single word filters
            [single] => {
                // Protocol names
                match *single {
                    "tcp" => return packet.transport_protocol == crate::capture::packet::TransportProtocol::Tcp,
                    "udp" => return packet.transport_protocol == crate::capture::packet::TransportProtocol::Udp,
                    "icmp" => return packet.transport_protocol == crate::capture::packet::TransportProtocol::Icmp,
                    _ => {}
                }

                // Try as port number
                if let Ok(port) = single.parse::<u16>() {
                    if packet.src_port == Some(port) || packet.dst_port == Some(port) {
                        return true;
                    }
                }

                // Try as IP address or prefix
                if let Some(ref src_ip) = packet.ip_src {
                    if src_ip.to_string().contains(single) {
                        return true;
                    }
                }
                if let Some(ref dst_ip) = packet.ip_dst {
                    if dst_ip.to_string().contains(single) {
                        return true;
                    }
                }

                // Check service/pattern match
                if let Some(ref pattern) = packet.pattern_match {
                    if pattern.to_lowercase().contains(single) {
                        return true;
                    }
                }
                if let Some(ref service) = packet.service_hint {
                    if service.to_lowercase().contains(single) {
                        return true;
                    }
                }

                false
            }
            // Fallback: simple contains matching on all fields
            _ => {
                let filter_combined = filter;

                // Check ports
                if let Some(src_port) = packet.src_port {
                    if src_port.to_string().contains(filter_combined) {
                        return true;
                    }
                }
                if let Some(dst_port) = packet.dst_port {
                    if dst_port.to_string().contains(filter_combined) {
                        return true;
                    }
                }

                // Check IPs
                if let Some(ref ip) = packet.ip_src {
                    if ip.to_string().contains(filter_combined) {
                        return true;
                    }
                }
                if let Some(ref ip) = packet.ip_dst {
                    if ip.to_string().contains(filter_combined) {
                        return true;
                    }
                }

                false
            }
        }
    }

    async fn export_dashboard(&mut self) {
        let data = serde_json::json!({
            "open_ports": self.open_ports,
            "inbound_connections": self.inbound_connections,
            "outbound_connections": self.outbound_connections,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });

        let filename = format!("dashboard_{}.json", chrono::Utc::now().format("%Y%m%d_%H%M%S"));
        if let Ok(json) = serde_json::to_string_pretty(&data) {
            if std::fs::write(&filename, json).is_ok() {
                self.set_status(format!("Exported to {}", filename));
            }
        }
    }

    async fn export_scan_results(&mut self) {
        if self.scanner_results.is_empty() {
            self.set_status("No scan results to export".to_string());
            return;
        }

        let data = serde_json::json!({
            "target": self.scanner_input,
            "port_range": format!("{:?}", self.scanner_port_range),
            "results": self.scanner_results,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });

        let filename = format!("scan_{}.json", chrono::Utc::now().format("%Y%m%d_%H%M%S"));
        if let Ok(json) = serde_json::to_string_pretty(&data) {
            if std::fs::write(&filename, json).is_ok() {
                self.set_status(format!("Exported to {}", filename));
            }
        }
    }

    async fn export_packets(&mut self) {
        if self.sniffer_packets.is_empty() {
            self.set_status("No packets to export".to_string());
            return;
        }

        let data = serde_json::json!({
            "packets": self.sniffer_packets,
            "filter": self.sniffer_filter,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });

        let filename = format!("packets_{}.json", chrono::Utc::now().format("%Y%m%d_%H%M%S"));
        if let Ok(json) = serde_json::to_string_pretty(&data) {
            if std::fs::write(&filename, json).is_ok() {
                self.set_status(format!("Exported to {}", filename));
            }
        }
    }

    pub fn get_shortcuts(&self) -> Vec<(&'static str, &'static str)> {
        // If status message is showing, prioritize ESC to dismiss
        if self.status_message.is_some() {
            return vec![
                ("Esc/Enter", "Dismiss"),
                ("Tab", "Next Tab"),
                ("Ctrl+Q", "Quit"),
            ];
        }

        let mut shortcuts = vec![
            ("Tab", "Next Tab"),
            ("Ctrl+T", "Theme"),
            ("Ctrl+Q", "Quit"),
        ];

        match self.current_tab {
            Tab::Dashboard => {
                shortcuts.extend([
                    ("←/→", "Switch Panel"),
                    ("↑/↓", "Scroll"),
                    ("e", "Export"),
                ]);
            }
            Tab::PortScanner => {
                match self.scanner_input_mode {
                    InputMode::Normal => {
                        shortcuts.extend([
                            ("i", "Edit Target"),
                            ("o", "Edit Ports"),
                            ("p", "Cycle Presets"),
                            ("s", "Start Scan"),
                            ("r", "Rerun Last"),
                            ("d", "Detection Mode"),
                            ("↑/↓", "Scroll"),
                            ("e", "Export"),
                        ]);
                    }
                    InputMode::Editing => {
                        let _field = match self.scanner_focus {
                            ScannerFocus::Target => "Target",
                            ScannerFocus::Ports => "Ports",
                        };
                        shortcuts.clear();
                        shortcuts.extend([
                            ("Tab", "Switch Field"),
                            ("Enter", "Confirm"),
                            ("Esc", "Cancel"),
                        ]);
                    }
                }
            }
            Tab::PacketSniffer => {
                if self.sniffer_show_help {
                    shortcuts.extend([
                        ("Esc/?", "Close Help"),
                    ]);
                } else {
                    match self.sniffer_filter_mode {
                        InputMode::Normal => {
                            shortcuts.extend([
                                ("Space", if self.sniffer_active { "Pause" } else { "Start" }),
                                ("f,/", "Filter"),
                                ("h", "Toggle Hex"),
                                ("?", "Help"),
                                ("c", "Clear"),
                                ("Enter", "Expand/Collapse"),
                                ("↑/↓", "Scroll"),
                                ("PgUp/Dn", "Page Scroll"),
                                ("Home/End", "Jump"),
                                ("e", "Export"),
                            ]);
                        }
                        InputMode::Editing => {
                            shortcuts.extend([
                                ("Enter/Esc", "Apply Filter"),
                            ]);
                        }
                    }
                }
            }
        }

        shortcuts
    }
}
