use ratatui::{
    prelude::*,
    widgets::{Block, Borders, List, ListItem, Paragraph},
};

use crate::app::{App, DashboardPanel};
use crate::network::connection::get_service_name;
use super::get_theme;
use super::theme::Theme;

pub fn draw(frame: &mut Frame, app: &App, area: Rect) {
    let theme = get_theme(app);

    // Split into three columns
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(33),
            Constraint::Percentage(34),
            Constraint::Percentage(33),
        ])
        .split(area);

    draw_open_ports(frame, app, chunks[0], &theme);
    draw_inbound(frame, app, chunks[1], &theme);
    draw_outbound(frame, app, chunks[2], &theme);
}

fn draw_open_ports(frame: &mut Frame, app: &App, area: Rect, theme: &Theme) {
    let is_focused = app.dashboard_panel == DashboardPanel::OpenPorts;

    let items: Vec<ListItem> = app
        .open_ports
        .iter()
        .enumerate()
        .skip(app.dashboard_scroll[0])
        .map(|(i, conn)| {
            let service = get_service_name(conn.local_port)
                .unwrap_or("unknown");

            let process = conn.process_name.as_deref().unwrap_or("-");

            let content = format!(
                "{:>5} │ {:12} │ {}",
                conn.local_port,
                service,
                process
            );

            let style = if i == app.dashboard_scroll[0] && is_focused {
                Style::default().bg(theme.selection_bg).fg(theme.accent)
            } else {
                Style::default().fg(theme.fg)
            };

            ListItem::new(Line::from(content)).style(style)
        })
        .collect();

    let border_style = if is_focused {
        Style::default().fg(theme.border_focused)
    } else {
        Style::default().fg(theme.border)
    };

    let block = Block::default()
        .title(format!(" Open Ports ({}) ", app.open_ports.len()))
        .title_style(Style::default().fg(if is_focused { theme.accent } else { theme.fg_dim }))
        .borders(Borders::ALL)
        .border_style(border_style);

    // Header
    let header = Paragraph::new(Line::from(vec![
        Span::styled(" Port │ Service      │ Process", Style::default().fg(theme.fg_dim)),
    ]));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.height > 1 {
        let header_area = Rect::new(inner.x, inner.y, inner.width, 1);
        let list_area = Rect::new(inner.x, inner.y + 1, inner.width, inner.height - 1);

        frame.render_widget(header, header_area);

        let list = List::new(items);
        frame.render_widget(list, list_area);
    }
}

fn draw_inbound(frame: &mut Frame, app: &App, area: Rect, theme: &Theme) {
    let is_focused = app.dashboard_panel == DashboardPanel::Inbound;

    let items: Vec<ListItem> = app
        .inbound_connections
        .iter()
        .enumerate()
        .skip(app.dashboard_scroll[1])
        .map(|(i, conn)| {
            let remote = conn.format_remote();
            let local_port = conn.local_port;
            let service = get_service_name(local_port).unwrap_or("-");

            let content = format!("{:21} → :{:<5} ({})", remote, local_port, service);

            let style = if i == app.dashboard_scroll[1] && is_focused {
                Style::default().bg(theme.selection_bg).fg(theme.accent)
            } else {
                Style::default().fg(theme.fg)
            };

            ListItem::new(Line::from(content)).style(style)
        })
        .collect();

    let border_style = if is_focused {
        Style::default().fg(theme.border_focused)
    } else {
        Style::default().fg(theme.border)
    };

    let block = Block::default()
        .title(format!(" Inbound ({}) ", app.inbound_connections.len()))
        .title_style(Style::default().fg(if is_focused { theme.accent } else { theme.fg_dim }))
        .borders(Borders::ALL)
        .border_style(border_style);

    let header = Paragraph::new(Line::from(vec![
        Span::styled(" Remote               → Local   Service", Style::default().fg(theme.fg_dim)),
    ]));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.height > 1 {
        let header_area = Rect::new(inner.x, inner.y, inner.width, 1);
        let list_area = Rect::new(inner.x, inner.y + 1, inner.width, inner.height - 1);

        frame.render_widget(header, header_area);

        let list = List::new(items);
        frame.render_widget(list, list_area);
    }
}

fn draw_outbound(frame: &mut Frame, app: &App, area: Rect, theme: &Theme) {
    let is_focused = app.dashboard_panel == DashboardPanel::Outbound;

    let items: Vec<ListItem> = app
        .outbound_connections
        .iter()
        .enumerate()
        .skip(app.dashboard_scroll[2])
        .map(|(i, conn)| {
            let remote = conn.format_remote();
            let local_port = conn.local_port;
            let remote_port = conn.remote_port.unwrap_or(0);
            let service = get_service_name(remote_port).unwrap_or("-");

            let content = format!(":{:<5} → {:21} ({})", local_port, remote, service);

            let style = if i == app.dashboard_scroll[2] && is_focused {
                Style::default().bg(theme.selection_bg).fg(theme.accent)
            } else {
                Style::default().fg(theme.fg)
            };

            ListItem::new(Line::from(content)).style(style)
        })
        .collect();

    let border_style = if is_focused {
        Style::default().fg(theme.border_focused)
    } else {
        Style::default().fg(theme.border)
    };

    let block = Block::default()
        .title(format!(" Outbound ({}) ", app.outbound_connections.len()))
        .title_style(Style::default().fg(if is_focused { theme.accent } else { theme.fg_dim }))
        .borders(Borders::ALL)
        .border_style(border_style);

    let header = Paragraph::new(Line::from(vec![
        Span::styled(" Local → Remote               Service", Style::default().fg(theme.fg_dim)),
    ]));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.height > 1 {
        let header_area = Rect::new(inner.x, inner.y, inner.width, 1);
        let list_area = Rect::new(inner.x, inner.y + 1, inner.width, inner.height - 1);

        frame.render_widget(header, header_area);

        let list = List::new(items);
        frame.render_widget(list, list_area);
    }
}
