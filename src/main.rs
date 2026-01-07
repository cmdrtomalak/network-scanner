mod app;
mod capture;
mod event;
mod network;
mod scanner;
mod ui;

use anyhow::Result;
use clap::Parser;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::prelude::*;
use std::io;

use app::App;
use event::{Event, EventHandler};

#[derive(Parser, Debug)]
#[command(name = "netscanner")]
#[command(about = "TUI network scanner with port scanning, connection monitoring, and packet sniffing")]
struct Args {
    /// Network interface to use for packet capture
    #[arg(short, long)]
    interface: Option<String>,

    /// Refresh rate in milliseconds for connection monitoring
    #[arg(short, long, default_value = "1000")]
    refresh_rate: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    // Check for root privileges
    #[cfg(unix)]
    {
        
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("Warning: Running without root privileges. Some features may be limited.");
            eprintln!("For full functionality, run with: sudo {}", args.interface.as_deref().unwrap_or("netscanner"));
            eprintln!();
        }
    }

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app and run
    let mut app = App::new(args.interface, args.refresh_rate);
    let event_handler = EventHandler::new(250);
    let res = run_app(&mut terminal, &mut app, event_handler).await;

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        eprintln!("Error: {err:?}");
    }

    Ok(())
}

async fn run_app<B: Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
    mut event_handler: EventHandler,
) -> Result<()> {
    app.start_background_tasks().await;

    loop {
        terminal.draw(|f| ui::draw(f, app))?;

        match event_handler.next().await? {
            Event::Tick => {
                app.on_tick().await;
            }
            Event::Key(key_event) => {
                if app.handle_key(key_event).await {
                    break;
                }
            }
            Event::Mouse(mouse_event) => {
                app.handle_mouse(mouse_event);
            }
            Event::Resize(_, _) => {}
        }
    }

    Ok(())
}
