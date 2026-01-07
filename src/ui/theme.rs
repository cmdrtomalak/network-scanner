use ratatui::style::Color;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThemeName {
    #[default]
    GruvboxDark,
    TwoDark,
    Leet, // 1337
}

impl ThemeName {
    pub fn next(self) -> Self {
        match self {
            ThemeName::GruvboxDark => ThemeName::TwoDark,
            ThemeName::TwoDark => ThemeName::Leet,
            ThemeName::Leet => ThemeName::GruvboxDark,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            ThemeName::GruvboxDark => "Gruvbox Dark",
            ThemeName::TwoDark => "One Dark",
            ThemeName::Leet => "1337",
        }
    }

    pub fn theme(&self) -> Theme {
        match self {
            ThemeName::GruvboxDark => GRUVBOX_DARK,
            ThemeName::TwoDark => TWO_DARK,
            ThemeName::Leet => LEET,
        }
    }
}

#[derive(Clone, Copy)]
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

// Gruvbox Dark theme (default)
// Based on https://github.com/morhetz/gruvbox
pub static GRUVBOX_DARK: Theme = Theme {
    bg: Color::Rgb(40, 40, 40),           // #282828 bg
    fg: Color::Rgb(235, 219, 178),        // #ebdbb2 fg
    fg_dim: Color::Rgb(146, 131, 116),    // #928374 gray
    accent: Color::Rgb(131, 165, 152),    // #83a598 blue
    accent_secondary: Color::Rgb(211, 134, 155), // #d3869b purple
    border: Color::Rgb(80, 73, 69),       // #504945 bg2
    border_focused: Color::Rgb(131, 165, 152), // #83a598 blue
    success: Color::Rgb(184, 187, 38),    // #b8bb26 green
    warning: Color::Rgb(250, 189, 47),    // #fabd2f yellow
    error: Color::Rgb(251, 73, 52),       // #fb4934 red
    info: Color::Rgb(131, 165, 152),      // #83a598 blue
    selection_bg: Color::Rgb(60, 56, 54), // #3c3836 bg1
};

// One Dark / TwoDark theme
// Based on Atom One Dark
pub static TWO_DARK: Theme = Theme {
    bg: Color::Rgb(40, 44, 52),           // #282c34
    fg: Color::Rgb(171, 178, 191),        // #abb2bf
    fg_dim: Color::Rgb(92, 99, 112),      // #5c6370
    accent: Color::Rgb(97, 175, 239),     // #61afef blue
    accent_secondary: Color::Rgb(198, 120, 221), // #c678dd purple
    border: Color::Rgb(62, 68, 81),       // #3e4451
    border_focused: Color::Rgb(97, 175, 239), // #61afef blue
    success: Color::Rgb(152, 195, 121),   // #98c379 green
    warning: Color::Rgb(229, 192, 123),   // #e5c07b yellow
    error: Color::Rgb(224, 108, 117),     // #e06c75 red
    info: Color::Rgb(86, 182, 194),       // #56b6c2 cyan
    selection_bg: Color::Rgb(55, 59, 69), // #373b45
};

// 1337 theme
// Hacker/Matrix inspired green theme
pub static LEET: Theme = Theme {
    bg: Color::Rgb(20, 20, 20),           // #141414 dark bg
    fg: Color::Rgb(180, 210, 115),        // #b4d273 primary green
    fg_dim: Color::Rgb(102, 102, 102),    // #666666 gray
    accent: Color::Rgb(255, 193, 37),     // #ffc125 gold/yellow
    accent_secondary: Color::Rgb(155, 185, 85), // #9bb955 green variant
    border: Color::Rgb(55, 55, 55),       // #373737
    border_focused: Color::Rgb(255, 193, 37), // #ffc125 gold
    success: Color::Rgb(155, 185, 85),    // #9bb955 green
    warning: Color::Rgb(255, 193, 37),    // #ffc125 gold
    error: Color::Rgb(255, 88, 88),       // #ff5858 red
    info: Color::Rgb(108, 153, 187),      // #6c99bb blue
    selection_bg: Color::Rgb(40, 40, 40), // #282828
};

