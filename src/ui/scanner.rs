use ratatui::{
    prelude::*,
    widgets::{Block, Borders, List, ListItem, Paragraph},
};

use crate::app::{App, InputMode, ScannerFocus};
use crate::scanner::{PortState, ServiceProbeLevel};
use super::theme::THEME;

pub fn draw(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Target input
            Constraint::Length(3),  // Port range input
            Constraint::Length(3),  // Options bar
            Constraint::Min(0),     // Results
        ])
        .split(area);

    draw_target_input(frame, app, chunks[0]);
    draw_port_input(frame, app, chunks[1]);
    draw_options(frame, app, chunks[2]);
    draw_results(frame, app, chunks[3]);
}

fn draw_target_input(frame: &mut Frame, app: &App, area: Rect) {
    let is_focused = app.scanner_input_mode == InputMode::Editing
        && app.scanner_focus == ScannerFocus::Target;

    let border_style = if is_focused {
        Style::default().fg(THEME.border_focused)
    } else {
        Style::default().fg(THEME.border)
    };

    let block = Block::default()
        .title(" Target (hostname or IP) - press 'i' to edit ")
        .title_style(Style::default().fg(if is_focused { THEME.accent } else { THEME.fg_dim }))
        .borders(Borders::ALL)
        .border_style(border_style);

    let input_text = if app.scanner_input.is_empty() && !is_focused {
        Span::styled("e.g., 192.168.1.1 or example.com", Style::default().fg(THEME.fg_dim))
    } else {
        Span::styled(&app.scanner_input, Style::default().fg(THEME.fg))
    };

    let paragraph = Paragraph::new(Line::from(vec![
        Span::raw(" "),
        input_text,
        if is_focused {
            Span::styled("█", Style::default().fg(THEME.accent))
        } else {
            Span::raw("")
        },
    ]))
    .block(block);

    frame.render_widget(paragraph, area);
}

fn draw_port_input(frame: &mut Frame, app: &App, area: Rect) {
    let is_focused = app.scanner_input_mode == InputMode::Editing
        && app.scanner_focus == ScannerFocus::Ports;

    let border_style = if is_focused {
        Style::default().fg(THEME.border_focused)
    } else {
        Style::default().fg(THEME.border)
    };

    // Show current selection and custom input option
    let current_preset = match app.scanner_selected_preset {
        0 => "Top 100",
        1 => "Top 1000",
        2 => "Full (1-65535)",
        3 => "Custom",
        _ => "Top 100",
    };

    let title = format!(" Ports: {} - press 'o' to edit, 'p' to cycle presets ", current_preset);

    let block = Block::default()
        .title(title)
        .title_style(Style::default().fg(if is_focused { THEME.accent } else { THEME.fg_dim }))
        .borders(Borders::ALL)
        .border_style(border_style);

    let input_text = if app.scanner_port_input.is_empty() && !is_focused {
        Span::styled("Custom: 22,80,443 or 1-1024 or 80", Style::default().fg(THEME.fg_dim))
    } else {
        Span::styled(&app.scanner_port_input, Style::default().fg(THEME.fg))
    };

    let paragraph = Paragraph::new(Line::from(vec![
        Span::raw(" "),
        input_text,
        if is_focused {
            Span::styled("█", Style::default().fg(THEME.accent))
        } else {
            Span::raw("")
        },
    ]))
    .block(block);

    frame.render_widget(paragraph, area);
}

fn draw_options(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(THEME.border));

    let port_range_str = app.scanner_port_range.display_name();
    let probe_str = match app.scanner_probe_level {
        ServiceProbeLevel::Banner => "Banner",
        ServiceProbeLevel::Deep => "Deep Probe",
    };

    let status = if app.scanner_running {
        Span::styled(" ● Scanning...", Style::default().fg(THEME.warning))
    } else {
        Span::styled(" ○ Ready", Style::default().fg(THEME.success))
    };

    let content = Line::from(vec![
        Span::styled(" Active: ", Style::default().fg(THEME.fg_dim)),
        Span::styled(port_range_str, Style::default().fg(THEME.accent)),
        Span::raw("  │  "),
        Span::styled("Detection: ", Style::default().fg(THEME.fg_dim)),
        Span::styled(probe_str, Style::default().fg(THEME.accent)),
        Span::raw("  │  "),
        status,
    ]);

    let paragraph = Paragraph::new(content).block(block);
    frame.render_widget(paragraph, area);
}

fn draw_results(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(format!(" Scan Results ({} open ports) ", app.scanner_results.len()))
        .title_style(Style::default().fg(THEME.fg_dim))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(THEME.border));

    if app.scanner_results.is_empty() {
        let message = if app.scanner_running {
            "Scanning in progress..."
        } else if app.scanner_input.is_empty() {
            "Enter a target and press 's' to start scanning"
        } else {
            "No results. Press 's' to scan."
        };

        let paragraph = Paragraph::new(message)
            .block(block)
            .style(Style::default().fg(THEME.fg_dim))
            .alignment(Alignment::Center);

        frame.render_widget(paragraph, area);
        return;
    }

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Header
    let header = Line::from(vec![
        Span::styled(
            format!(" {:>5} │ {:8} │ {:15} │ {:20} │ Banner",
                "Port", "State", "Service", "Version"),
            Style::default().fg(THEME.fg_dim),
        ),
    ]);

    let header_area = Rect::new(inner.x, inner.y, inner.width, 1);
    frame.render_widget(Paragraph::new(header), header_area);

    // Results list
    let list_area = Rect::new(inner.x, inner.y + 1, inner.width, inner.height.saturating_sub(1));

    let items: Vec<ListItem> = app
        .scanner_results
        .iter()
        .enumerate()
        .skip(app.scanner_scroll)
        .map(|(i, result)| {
            let state_style = match result.state {
                PortState::Open => Style::default().fg(THEME.success),
                PortState::Closed => Style::default().fg(THEME.error),
                PortState::Filtered => Style::default().fg(THEME.warning),
            };

            let state_str = match result.state {
                PortState::Open => "open",
                PortState::Closed => "closed",
                PortState::Filtered => "filtered",
            };

            let service = result.service.as_deref().unwrap_or("-");
            let version = result.version.as_deref().unwrap_or("-");
            let banner = result.banner.as_deref().unwrap_or("-");
            let banner_truncated: String = banner.chars().take(30).collect();

            let content = Line::from(vec![
                Span::raw(format!(" {:>5} │ ", result.port)),
                Span::styled(format!("{:8}", state_str), state_style),
                Span::raw(" │ "),
                Span::styled(format!("{:15}", service), Style::default().fg(THEME.accent)),
                Span::raw(" │ "),
                Span::raw(format!("{:20} │ ", version)),
                Span::styled(banner_truncated, Style::default().fg(THEME.fg_dim)),
            ]);

            let style = if i == app.scanner_scroll {
                Style::default().bg(THEME.selection_bg)
            } else {
                Style::default()
            };

            ListItem::new(content).style(style)
        })
        .collect();

    let list = List::new(items);
    frame.render_widget(list, list_area);
}
