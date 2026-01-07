use anyhow::Result;
use crossterm::event::{self, KeyEvent, MouseEvent};
use std::time::Duration;
use tokio::sync::mpsc;

#[derive(Debug)]
pub enum Event {
    Tick,
    Key(KeyEvent),
    Mouse(MouseEvent),
    Resize(u16, u16),
}

pub struct EventHandler {
    rx: mpsc::UnboundedReceiver<Event>,
    _tx: mpsc::UnboundedSender<Event>,
}

impl EventHandler {
    pub fn new(tick_rate_ms: u64) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let tx_clone = tx.clone();

        tokio::spawn(async move {
            let tick_rate = Duration::from_millis(tick_rate_ms);
            loop {
                if event::poll(tick_rate).unwrap_or(false) {
                    match event::read() {
                        Ok(event::Event::Key(key)) => {
                            if tx_clone.send(Event::Key(key)).is_err() {
                                break;
                            }
                        }
                        Ok(event::Event::Mouse(mouse)) => {
                            if tx_clone.send(Event::Mouse(mouse)).is_err() {
                                break;
                            }
                        }
                        Ok(event::Event::Resize(w, h)) => {
                            if tx_clone.send(Event::Resize(w, h)).is_err() {
                                break;
                            }
                        }
                        _ => {}
                    }
                } else if tx_clone.send(Event::Tick).is_err() {
                    break;
                }
            }
        });

        Self { rx, _tx: tx }
    }

    pub async fn next(&mut self) -> Result<Event> {
        self.rx.recv().await.ok_or_else(|| anyhow::anyhow!("Event channel closed"))
    }
}
