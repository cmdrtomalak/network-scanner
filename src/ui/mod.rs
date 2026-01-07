mod dashboard;
mod scanner;
mod sniffer;
mod shortcuts;
mod theme;

use ratatui::prelude::*;

use crate::app::{App, Tab};

pub use theme::THEME;

pub fn draw(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Tab bar
            Constraint::Min(0),     // Content
            Constraint::Length(2),  // Shortcuts bar
        ])
        .split(frame.area());

    // Draw tab bar
    draw_tabs(frame, app, chunks[0]);

    // Draw main content based on current tab
    match app.current_tab {
        Tab::Dashboard => dashboard::draw(frame, app, chunks[1]),
        Tab::PortScanner => scanner::draw(frame, app, chunks[1]),
        Tab::PacketSniffer => sniffer::draw(frame, app, chunks[1]),
    }

    // Draw shortcuts bar
    shortcuts::draw(frame, app, chunks[2]);

    // Draw status message if present
    if let Some(ref msg) = app.status_message {
        let area = centered_rect(60, 3, frame.area());
        let block = ratatui::widgets::Block::default()
            .borders(ratatui::widgets::Borders::ALL)
            .border_style(Style::default().fg(THEME.accent))
            .style(Style::default().bg(THEME.bg));
        let paragraph = ratatui::widgets::Paragraph::new(msg.as_str())
            .block(block)
            .alignment(Alignment::Center);
        frame.render_widget(ratatui::widgets::Clear, area);
        frame.render_widget(paragraph, area);
    }
}

fn draw_tabs(frame: &mut Frame, app: &App, area: Rect) {
    use ratatui::widgets::{Block, Borders, Tabs};

    let titles: Vec<Line> = [Tab::Dashboard, Tab::PortScanner, Tab::PacketSniffer]
        .iter()
        .map(|t| {
            let style = if *t == app.current_tab {
                Style::default().fg(THEME.accent).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(THEME.fg_dim)
            };
            Line::from(Span::styled(t.title(), style))
        })
        .collect();

    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(THEME.border))
                .title(" NetScanner ")
                .title_style(Style::default().fg(THEME.accent).add_modifier(Modifier::BOLD)),
        )
        .select(app.current_tab as usize)
        .style(Style::default().fg(THEME.fg))
        .highlight_style(Style::default().fg(THEME.accent).add_modifier(Modifier::BOLD))
        .divider(Span::raw(" │ "));

    frame.render_widget(tabs, area);
}

fn centered_rect(percent_x: u16, height: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - height.min(100)) / 2),
            Constraint::Length(height),
            Constraint::Percentage((100 - height.min(100)) / 2),
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
