# NetScanner

A Terminal User Interface (TUI) network scanner written in Rust. NetScanner provides real-time network monitoring, port scanning, and packet capture capabilities in a single, easy-to-use terminal application.

## Features

### Machine Info Tab
Monitor your local machine's network activity in real-time:
- **Open Ports**: View all ports currently listening on your machine with associated services and processes
- **Inbound Connections**: Track incoming connections from remote hosts
- **Outbound Connections**: Monitor outgoing connections to remote services
- Configurable refresh rate for connection monitoring
- Scrollable panels with keyboard navigation

### Port Scanner Tab
Scan remote hosts for open ports with service detection:
- Scan by hostname or IP address (supports LAN hostnames and mDNS)
- Multiple port range presets:
  - Top 100 most common ports
  - Top 1000 most common ports
  - Full scan (ports 1-65535)
  - Custom port ranges (e.g., `22,80,443` or `1-1024`)
- Service detection modes:
  - Banner grabbing (fast)
  - Deep probe detection (thorough, nmap-style)
- Re-run previous scans with a single keypress
- Export results to JSON

### Packet Sniffer Tab
Capture and analyze network packets in real-time:
- Start/pause packet capture on any network interface
- BPF-style filtering:
  - `port 80` - filter by port number
  - `host 192.168.1.1` - filter by IP address
  - `tcp`, `udp`, `icmp` - filter by protocol
  - `net 192.168` - filter by network prefix
  - `src port 443`, `dst host 10.0.0.1` - directional filters
- Expandable packet details showing:
  - Connection info (source/destination IP and port)
  - TCP flags with descriptions
  - IP header details (TTL, protocol)
  - Payload data (hex or plain text view)
  - Security notes for identified traffic patterns
- Protocol pattern recognition with built-in help (`?` key)
- Page up/down and Home/End for fast navigation
- Export captured packets to JSON

### Additional Features
- **Theme Support**: Three color themes available (Gruvbox Dark, One Dark, 1337)
- **Context-Sensitive Shortcuts**: Bottom bar shows available keyboard shortcuts for current view
- **JSON Export**: Export data from any tab for further analysis
- **Cross-Platform**: Works on macOS and Linux

## Requirements

- Rust 1.70 or later
- libpcap development libraries
  - macOS: Included with Xcode Command Line Tools
  - Debian/Ubuntu: `sudo apt install libpcap-dev`
  - Fedora/RHEL: `sudo dnf install libpcap-devel`
- Root/sudo privileges (required for packet capture and some scan types)

## Building

```bash
# Clone the repository
git clone <repository-url>
cd network-scanner

# Build release binary
cargo build --release

# Binary will be at ./target/release/netscanner
```

## Usage

```bash
# Run with default settings (requires sudo for full functionality)
sudo ./target/release/netscanner

# Specify network interface for packet capture
sudo ./target/release/netscanner -i en0

# Set custom refresh rate for connection monitoring (milliseconds)
sudo ./target/release/netscanner -r 500

# Combine options
sudo ./target/release/netscanner -i eth0 -r 2000
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-i, --interface <NAME>` | Network interface for packet capture (e.g., en0, eth0, lo0) |
| `-r, --refresh-rate <MS>` | Refresh rate in milliseconds for connection monitoring (default: 1000) |
| `-h, --help` | Show help message |

## Keyboard Shortcuts

### Global
| Key | Action |
|-----|--------|
| `Tab` | Switch to next tab |
| `Shift+Tab` | Switch to previous tab |
| `Ctrl+T` | Cycle through themes |
| `Ctrl+Q` | Quit application |
| `Esc` / `Enter` | Dismiss status messages |

### Machine Info Tab
| Key | Action |
|-----|--------|
| `h` / `l` | Switch between panels |
| `j` / `Down` | Scroll down |
| `k` / `Up` | Scroll up |
| `e` | Export to JSON |

### Port Scanner Tab
| Key | Action |
|-----|--------|
| `i` | Edit target hostname/IP |
| `o` | Edit custom port range |
| `p` | Cycle through port presets |
| `d` | Toggle detection mode (Banner/Deep) |
| `s` | Start scan |
| `r` | Re-run last scan |
| `j` / `Down` | Scroll results down |
| `k` / `Up` | Scroll results up |
| `e` | Export results to JSON |

### Packet Sniffer Tab
| Key | Action |
|-----|--------|
| `Space` | Start/pause capture |
| `f` / `/` | Open filter input |
| `h` | Toggle hex/text payload display |
| `?` | Show protocol help overlay |
| `c` | Clear captured packets |
| `Enter` | Expand/collapse packet details |
| `j` / `Down` | Scroll down |
| `k` / `Up` | Scroll up |
| `Page Up` | Scroll up 20 packets |
| `Page Down` | Scroll down 20 packets |
| `Home` | Jump to first packet |
| `End` | Jump to last packet |
| `e` | Export packets to JSON |

## Filter Syntax (Packet Sniffer)

The packet sniffer supports BPF-like filter syntax:

| Filter | Description |
|--------|-------------|
| `port 80` | Match packets with source OR destination port 80 |
| `src port 443` | Match packets with source port 443 |
| `dst port 22` | Match packets with destination port 22 |
| `host 192.168.1.1` | Match packets involving this IP (either direction) |
| `src host 10.0.0.1` | Match packets from this IP |
| `dst host 10.0.0.1` | Match packets to this IP |
| `net 192.168` | Match packets with IPs starting with this prefix |
| `tcp` | Match TCP packets only |
| `udp` | Match UDP packets only |
| `icmp` | Match ICMP packets only |
| `80` | Single number matches as port |
| `http` | Match by service/pattern name |

## Exported JSON Format

### Dashboard Export
```json
{
  "open_ports": [...],
  "inbound_connections": [...],
  "outbound_connections": [...],
  "timestamp": "2024-01-07T12:00:00Z"
}
```

### Scan Results Export
```json
{
  "target": "192.168.1.1",
  "port_range": "Top100",
  "results": [...],
  "timestamp": "2024-01-07T12:00:00Z"
}
```

### Packet Capture Export
```json
{
  "packets": [...],
  "filter": "port 80",
  "timestamp": "2024-01-07T12:00:00Z"
}
```

## Security Notes

- This tool requires elevated privileges (sudo) for packet capture and certain scan operations
- Use responsibly and only on networks you own or have permission to test
- Port scanning and packet sniffing may be illegal without proper authorization
- The tool is intended for network diagnostics, security testing, and educational purposes

## License

MIT
