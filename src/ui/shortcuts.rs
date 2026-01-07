use ratatui::{
    prelude::*,
    widgets::{Block, Borders},
};

use crate::app::App;
use super::theme::THEME;

pub fn draw(frame: &mut Frame, app: &App, area: Rect) {
    let shortcuts = app.get_shortcuts();

    let spans: Vec<Span> = shortcuts
        .iter()
        .flat_map(|(key, desc)| {
            vec![
                Span::styled(format!(" {} ", key), Style::default()
                    .bg(THEME.accent)
                    .fg(THEME.bg)
                    .add_modifier(Modifier::BOLD)),
                Span::styled(format!(" {} ", desc), Style::default().fg(THEME.fg_dim)),
                Span::raw(" "),
            ]
        })
        .collect();

    let block = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(THEME.border));

    let paragraph = ratatui::widgets::Paragraph::new(Line::from(spans))
        .block(block)
        .style(Style::default().bg(THEME.bg));

    frame.render_widget(paragraph, area);
}
