use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, Wrap},
};

use crate::app::{App, InputMode};
use crate::capture::protocol_hints::format_help_text;
use super::get_theme;
use super::theme::Theme;

pub fn draw(frame: &mut Frame, app: &App, area: Rect) {
    let theme = get_theme(app);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Controls bar
            Constraint::Length(3),  // Filter bar
            Constraint::Min(0),     // Packet list
        ])
        .split(area);

    draw_controls(frame, app, chunks[0], &theme);
    draw_filter(frame, app, chunks[1], &theme);
    draw_packets(frame, app, chunks[2], &theme);

    // Draw help overlay if active
    if app.sniffer_show_help {
        draw_help_overlay(frame, area, &theme);
    }
}

fn draw_controls(frame: &mut Frame, app: &App, area: Rect, theme: &Theme) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border));

    let status = if app.sniffer_active {
        Span::styled(" ● Capturing", Style::default().fg(theme.success))
    } else {
        Span::styled(" ○ Paused", Style::default().fg(theme.fg_dim))
    };

    let hex_mode = if app.sniffer_show_hex {
        Span::styled("Hex", Style::default().fg(theme.accent))
    } else {
        Span::styled("Text", Style::default().fg(theme.accent))
    };

    let content = Line::from(vec![
        status,
        Span::raw("  │  "),
        Span::styled("Packets: ", Style::default().fg(theme.fg_dim)),
        Span::styled(
            app.sniffer_packets.len().to_string(),
            Style::default().fg(theme.fg),
        ),
        Span::raw("  │  "),
        Span::styled("Display: ", Style::default().fg(theme.fg_dim)),
        hex_mode,
        Span::raw("  │  "),
        Span::styled("Interface: ", Style::default().fg(theme.fg_dim)),
        Span::styled(
            app.interface.as_deref().unwrap_or("default"),
            Style::default().fg(theme.fg),
        ),
    ]);

    let paragraph = Paragraph::new(content).block(block);
    frame.render_widget(paragraph, area);
}

fn draw_filter(frame: &mut Frame, app: &App, area: Rect, theme: &Theme) {
    let is_editing = app.sniffer_filter_mode == InputMode::Editing;

    let border_style = if is_editing {
        Style::default().fg(theme.border_focused)
    } else {
        Style::default().fg(theme.border)
    };

    let block = Block::default()
        .title(" Filter (BPF syntax: 'port 80', 'host 192.168.1.1', 'tcp') ")
        .title_style(Style::default().fg(if is_editing { theme.accent } else { theme.fg_dim }))
        .borders(Borders::ALL)
        .border_style(border_style);

    let filter_text = if app.sniffer_filter.is_empty() && !is_editing {
        Span::styled("Press 'f' to add filter...", Style::default().fg(theme.fg_dim))
    } else {
        Span::styled(&app.sniffer_filter, Style::default().fg(theme.fg))
    };

    let paragraph = Paragraph::new(Line::from(vec![
        Span::raw(" "),
        filter_text,
        if is_editing {
            Span::styled("█", Style::default().fg(theme.accent))
        } else {
            Span::raw("")
        },
    ]))
    .block(block);

    frame.render_widget(paragraph, area);
}

fn draw_packets(frame: &mut Frame, app: &App, area: Rect, theme: &Theme) {
    let filtered = app.filtered_packets();
    let total_count = app.sniffer_packets.len();
    let filtered_count = filtered.len();

    let title = if app.sniffer_filter.is_empty() {
        format!(" Captured Packets ({}) ", total_count)
    } else {
        format!(" Captured Packets ({}/{} matched) ", filtered_count, total_count)
    };

    let block = Block::default()
        .title(title)
        .title_style(Style::default().fg(theme.fg_dim))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border));

    if filtered.is_empty() {
        let message = if app.sniffer_active {
            if app.sniffer_filter.is_empty() {
                "Waiting for packets..."
            } else {
                "No packets match filter"
            }
        } else {
            "Press Space to start capturing"
        };

        let paragraph = Paragraph::new(message)
            .block(block)
            .style(Style::default().fg(theme.fg_dim))
            .alignment(Alignment::Center);

        frame.render_widget(paragraph, area);
        return;
    }

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Build packet list with expandable tree
    let mut items: Vec<ListItem> = Vec::new();
    let visible_height = inner.height as usize;

    for (display_idx, (original_idx, packet)) in filtered.iter().enumerate().skip(app.sniffer_scroll) {
        if items.len() >= visible_height {
            break;
        }

        let is_selected = display_idx == app.sniffer_scroll;
        let is_expanded = app.sniffer_expanded.get(original_idx).copied().unwrap_or(false);

        // Tree indicator
        let tree_icon = if is_expanded { "▼" } else { "▶" };

        // Protocol color
        let proto_style = match packet.transport_protocol {
            crate::capture::packet::TransportProtocol::Tcp => Style::default().fg(theme.info),
            crate::capture::packet::TransportProtocol::Udp => Style::default().fg(theme.success),
            crate::capture::packet::TransportProtocol::Icmp => Style::default().fg(theme.warning),
            _ => Style::default().fg(theme.fg_dim),
        };

        // Main packet line
        let time = packet.timestamp.format("%H:%M:%S%.3f");
        let summary = packet.summary();
        let hint = packet.pattern_match.as_deref().unwrap_or("");

        let line = Line::from(vec![
            Span::styled(tree_icon, Style::default().fg(theme.accent)),
            Span::raw(" "),
            Span::styled(format!("{}", time), Style::default().fg(theme.fg_dim)),
            Span::raw(" "),
            Span::styled(summary, proto_style),
            if !hint.is_empty() {
                Span::styled(format!(" [{}]", hint), Style::default().fg(theme.accent_secondary))
            } else {
                Span::raw("")
            },
        ]);

        let style = if is_selected {
            Style::default().bg(theme.selection_bg)
        } else {
            Style::default()
        };

        items.push(ListItem::new(line).style(style));

        // Expanded details
        if is_expanded && items.len() < visible_height {
            // Connection info
            items.push(ListItem::new(Line::from(vec![
                Span::raw("   ├─ "),
                Span::styled("Connection: ", Style::default().fg(theme.fg_dim)),
                Span::styled(
                    format!(
                        "{}:{} → {}:{}",
                        packet.ip_src.map(|ip| ip.to_string()).unwrap_or("?".into()),
                        packet.src_port.map(|p| p.to_string()).unwrap_or("?".into()),
                        packet.ip_dst.map(|ip| ip.to_string()).unwrap_or("?".into()),
                        packet.dst_port.map(|p| p.to_string()).unwrap_or("?".into()),
                    ),
                    Style::default().fg(theme.fg),
                ),
            ])));

            // Protocol headers
            if let Some(flags) = &packet.tcp_flags {
                items.push(ListItem::new(Line::from(vec![
                    Span::raw("   ├─ "),
                    Span::styled("TCP Flags: ", Style::default().fg(theme.fg_dim)),
                    Span::styled(flags.to_string(), Style::default().fg(theme.info)),
                    Span::raw(" - "),
                    Span::styled(flags.describe(), Style::default().fg(theme.fg_dim)),
                ])));
            }

            // TTL and protocol
            items.push(ListItem::new(Line::from(vec![
                Span::raw("   ├─ "),
                Span::styled("IP: ", Style::default().fg(theme.fg_dim)),
                Span::styled(
                    format!(
                        "TTL={}, Proto={}",
                        packet.ip_ttl.unwrap_or(0),
                        packet.ip_protocol.unwrap_or(0)
                    ),
                    Style::default().fg(theme.fg),
                ),
            ])));

            // Payload
            if !packet.payload.is_empty() {
                let payload_display = if app.sniffer_show_hex {
                    // Show first line of hex dump
                    let hex: String = packet.payload.iter()
                        .take(16)
                        .map(|b| format!("{:02x} ", b))
                        .collect();
                    format!("{}", hex.trim())
                } else {
                    // Show ASCII
                    packet.ascii_dump().chars().take(50).collect::<String>()
                };

                items.push(ListItem::new(Line::from(vec![
                    Span::raw("   └─ "),
                    Span::styled("Payload: ", Style::default().fg(theme.fg_dim)),
                    Span::styled(payload_display, Style::default().fg(theme.fg)),
                    if packet.payload.len() > 50 {
                        Span::styled("...", Style::default().fg(theme.fg_dim))
                    } else {
                        Span::raw("")
                    },
                ])));
            }

            // Pattern hint with security note
            if let Some(ref pattern) = packet.pattern_match {
                if let Some(hint) = crate::capture::protocol_hints::get_protocol_help(pattern) {
                    items.push(ListItem::new(Line::from(vec![
                        Span::raw("   └─ "),
                        Span::styled("⚠ ", Style::default().fg(theme.warning)),
                        Span::styled(hint.security_notes, Style::default().fg(theme.warning)),
                    ])));
                }
            }
        }
    }

    let list = List::new(items);
    frame.render_widget(list, inner);

    // Scrollbar
    if app.sniffer_packets.len() > visible_height {
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight);
        let mut scrollbar_state = ScrollbarState::new(app.sniffer_packets.len())
            .position(app.sniffer_scroll);
        frame.render_stateful_widget(scrollbar, inner, &mut scrollbar_state);
    }
}

fn draw_help_overlay(frame: &mut Frame, area: Rect, theme: &Theme) {
    // Create centered overlay
    let overlay_area = centered_rect(80, 80, area);

    frame.render_widget(Clear, overlay_area);

    let block = Block::default()
        .title(" Traffic Pattern Help (press Esc to close) ")
        .title_style(Style::default().fg(theme.accent).add_modifier(Modifier::BOLD))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border_focused))
        .style(Style::default().bg(theme.bg));

    let help_text = format_help_text();

    let paragraph = Paragraph::new(help_text)
        .block(block)
        .style(Style::default().fg(theme.fg))
        .wrap(Wrap { trim: false });

    frame.render_widget(paragraph, overlay_area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
