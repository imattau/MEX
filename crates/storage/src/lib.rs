use common::Order;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LogEntry {
    OrderAdded(Order),
    OrderMatched {
        buy_order_id: [u8; 32],
        sell_order_id: [u8; 32],
        price: u64,
        amount: u64,
    },
    OrderCancelled([u8; 32]),
}

pub struct TradeLogger {
    file_path: PathBuf,
    writer: Mutex<File>,
}

impl TradeLogger {
    pub fn new(path: PathBuf) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)?;
        Ok(Self {
            file_path: path,
            writer: Mutex::new(file),
        })
    }

    pub fn append(&self, entry: LogEntry) -> std::io::Result<()> {
        let serialized = serde_json::to_string(&entry)?;
        let mut guard = self.writer.lock().unwrap();
        writeln!(guard, "{}", serialized)?;
        guard.flush()?;
        Ok(())
    }

    pub fn recover(&self) -> std::io::Result<Vec<LogEntry>> {
        let file = File::open(&self.file_path)?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();

        for line in reader.lines() {
            let line = line?;
            if !line.trim().is_empty() {
                if let Ok(entry) = serde_json::from_str::<LogEntry>(&line) {
                    entries.push(entry);
                }
            }
        }
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{Order, OrderSide};

    #[test]
    fn test_trade_logger_append_and_recover() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_trade_log.jsonl");
        if path.exists() {
            let _ = std::fs::remove_file(&path);
        }

        let logger = TradeLogger::new(path.clone()).unwrap();

        let order = Order {
            id: [1u8; 32],
            trader: [2u8; 32],
            symbol: "ETH-USD".to_string(),
            side: OrderSide::Buy,
            price: 3000,
            amount: 5,
            signature: Vec::new(),
            nonce: 0,
            expiry: 0,
        };

        logger.append(LogEntry::OrderAdded(order.clone())).unwrap();
        logger.append(LogEntry::OrderMatched {
            buy_order_id: [1u8; 32],
            sell_order_id: [3u8; 32],
            price: 3000,
            amount: 5,
        }).unwrap();

        let recovered = logger.recover().unwrap();
        assert_eq!(recovered.len(), 2);
        
        match &recovered[0] {
            LogEntry::OrderAdded(o) => assert_eq!(o.id, order.id),
            _ => panic!("Expected OrderAdded"),
        }

        let _ = std::fs::remove_file(&path);
    }
}
