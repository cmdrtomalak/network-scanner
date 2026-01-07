use ratatui::{
    prelude::*,
    widgets::{Block, Borders},
};

use crate::app::App;
use super::get_theme;

pub fn draw(frame: &mut Frame, app: &App, area: Rect) {
    let theme = get_theme(app);
    let shortcuts = app.get_shortcuts();

    let spans: Vec<Span> = shortcuts
        .iter()
        .flat_map(|(key, desc)| {
            vec![
                Span::styled(format!(" {} ", key), Style::default()
                    .bg(theme.accent)
                    .fg(theme.bg)
                    .add_modifier(Modifier::BOLD)),
                Span::styled(format!(" {} ", desc), Style::default().fg(theme.fg_dim)),
                Span::raw(" "),
            ]
        })
        .collect();

    let block = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(theme.border));

    let paragraph = ratatui::widgets::Paragraph::new(Line::from(spans))
        .block(block)
        .style(Style::default().bg(theme.bg));

    frame.render_widget(paragraph, area);
}
