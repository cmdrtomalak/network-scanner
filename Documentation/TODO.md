# NetScanner TODO

## Completed Features

- [x] Project setup with Cargo and dependencies
- [x] TUI framework with ratatui
- [x] Tab-based navigation (Dashboard, Port Scanner, Packet Sniffer)
- [x] Dark theme with consistent styling
- [x] Bottom keyboard shortcuts bar (context-sensitive)
- [x] Dashboard tab
  - [x] Open ports panel
  - [x] Inbound connections panel
  - [x] Outbound connections panel
  - [x] Scrollable panels
  - [x] Panel focus switching
- [x] Port Scanner tab
  - [x] Target input field (hostname/IP)
  - [x] Port range presets (Top 100, Top 1000, Full)
  - [x] Concurrent TCP connect scanning
  - [x] Banner grabbing service detection
  - [x] Deep probe mode for enhanced detection
  - [x] Scrollable results list
  - [x] Re-run last scan capability
- [x] Packet Sniffer tab
  - [x] Start/pause capture controls
  - [x] BPF filter support
  - [x] Scrollable packet list
  - [x] Expandable packet tree view
  - [x] Connection info display
  - [x] Protocol headers display
  - [x] TCP flags with descriptions
  - [x] Hex/text payload toggle
  - [x] Traffic pattern identification
  - [x] Help overlay with protocol hints
- [x] JSON export for all tabs
- [x] Cross-platform support (macOS + Linux)
- [x] Documentation (DESIGN.md)

## In Progress

- [ ] Full packet receiver integration in sniffer
- [ ] Real-time packet updates in UI

## Planned Features

### Core Enhancements
- [ ] Custom port range input parsing
- [ ] Configurable refresh rate UI control
- [ ] Interface selection dialog
- [ ] Connection history tracking
- [ ] Packet search functionality

### Port Scanner Improvements
- [ ] UDP scanning support
- [ ] SYN scan (half-open, requires raw sockets)
- [ ] OS fingerprinting
- [ ] Version detection scripts
- [ ] Scan scheduling
- [ ] Scan templates/profiles

### Packet Sniffer Improvements
- [ ] Save captures to PCAP format
- [ ] Load PCAP files for analysis
- [ ] Follow TCP stream
- [ ] Protocol dissectors (HTTP, DNS, etc.)
- [ ] Packet statistics view
- [ ] Capture ring buffer (limit memory usage)
- [ ] Named service filters (e.g., "http" → port 80)

### Dashboard Improvements
- [ ] Connection graphs/charts
- [ ] Process tree view
- [ ] Geographic IP lookup
- [ ] DNS reverse lookup
- [ ] Connection alerts

### UI/UX
- [ ] Mouse support for clicking
- [ ] Light theme option
- [ ] Custom key bindings
- [ ] Configuration file
- [ ] Session persistence
- [ ] Command palette (fuzzy search)

### Export/Integration
- [ ] CSV export
- [ ] HTML report generation
- [ ] Integration with external tools
- [ ] Clipboard copy for selected items

### Performance
- [ ] Optimize large packet list rendering
- [ ] Lazy loading for scan results
- [ ] Connection pooling for scans

## Known Issues

- [ ] Warnings for unused code (reserved for future use)
- [ ] Packet sniffer receiver needs UI integration
- [ ] Some service detection may timeout

## Technical Debt

- [ ] Add comprehensive error handling
- [ ] Add unit tests
- [ ] Add integration tests
- [ ] Improve logging
- [ ] Add benchmarks
