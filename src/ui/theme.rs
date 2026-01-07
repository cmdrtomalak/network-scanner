use ratatui::style::Color;

pub struct Theme {
    pub bg: Color,
    pub fg: Color,
    pub fg_dim: Color,
    pub accent: Color,
    pub accent_secondary: Color,
    pub border: Color,
    pub border_focused: Color,
    pub success: Color,
    pub warning: Color,
    pub error: Color,
    pub info: Color,
    pub selection_bg: Color,
}

pub static THEME: Theme = Theme {
    bg: Color::Rgb(22, 22, 30),
    fg: Color::Rgb(220, 220, 230),
    fg_dim: Color::Rgb(120, 120, 140),
    accent: Color::Rgb(97, 175, 239),
    accent_secondary: Color::Rgb(198, 120, 221),
    border: Color::Rgb(60, 60, 80),
    border_focused: Color::Rgb(97, 175, 239),
    success: Color::Rgb(152, 195, 121),
    warning: Color::Rgb(229, 192, 123),
    error: Color::Rgb(224, 108, 117),
    info: Color::Rgb(86, 182, 194),
    selection_bg: Color::Rgb(40, 44, 52),
};
