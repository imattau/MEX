use common::Order;
use serde::{Deserialize, Serialize};
use std::path::Path;

static SEQ_KEY: &[u8] = b"__seq__";

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
    db: sled::Db,
}

impl TradeLogger {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, sled::Error> {
        let db = sled::open(path)?;
        Ok(Self { db })
    }

    pub fn append(&self, entry: LogEntry) -> Result<(), String> {
        let seq = self
            .db
            .fetch_and_update(SEQ_KEY, |old| {
                let current = old
                    .and_then(|b| <[u8; 8]>::try_from(b.as_ref()).ok())
                    .map(u64::from_be_bytes)
                    .unwrap_or(0);
                let next = current
                    .checked_add(1)
                    .expect("Sequence counter overflowed u64");
                Some(sled::IVec::from(next.to_be_bytes().to_vec()))
            })
            .map_err(|e| format!("Failed to fetch sequence: {}", e))?;

        let current_seq = seq
            .and_then(|b| <[u8; 8]>::try_from(b.as_ref()).ok())
            .map(u64::from_be_bytes)
            .unwrap_or(0);

        let key = current_seq.to_be_bytes();
        let value =
            serde_json::to_vec(&entry).map_err(|e| format!("Serialization failed: {}", e))?;

        self.db
            .insert(key, sled::IVec::from(value))
            .map_err(|e| format!("Insert failed: {}", e))?;

        self.db
            .flush()
            .map_err(|e| format!("Flush failed: {}", e))?;

        Ok(())
    }

    pub fn recover(&self) -> impl Iterator<Item = Result<LogEntry, String>> + '_ {
        self.db.iter().values().filter_map(|v| {
            let bytes = v.ok()?;
            if bytes.len() == 8 {
                return None;
            }
            match serde_json::from_slice::<LogEntry>(&bytes) {
                Ok(entry) => Some(Ok(entry)),
                Err(_) => None,
            }
        })
    }

    pub fn recover_all(&self) -> Result<Vec<LogEntry>, String> {
        self.recover().collect()
    }

    pub fn compact(&self) -> Result<usize, String> {
        let reclaimed = self
            .db
            .flush()
            .map_err(|e| format!("Flush failed: {}", e))?;
        Ok(reclaimed as usize)
    }

    pub fn size_on_disk(&self) -> u64 {
        self.db.size_on_disk().unwrap_or(0)
    }

    pub fn len(&self) -> usize {
        self.db
            .iter()
            .values()
            .filter(|v| v.as_ref().map(|b| b.len() != 8).unwrap_or(false))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{Order, OrderSide, SettlementPreference, SettlementRequester};

    #[test]
    fn test_trade_logger_append_and_recover() {
        let dir = std::env::temp_dir().join("test_trade_log_sled");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).ok();

        let logger = TradeLogger::open(&dir).unwrap();

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
            settlement_preference: SettlementPreference::Standard,
            settlement_requester: SettlementRequester::Seller,
        };

        logger.append(LogEntry::OrderAdded(order.clone())).unwrap();
        logger
            .append(LogEntry::OrderMatched {
                buy_order_id: [1u8; 32],
                sell_order_id: [3u8; 32],
                price: 3000,
                amount: 5,
            })
            .unwrap();

        let recovered = logger.recover_all().unwrap();
        assert_eq!(recovered.len(), 2);

        match &recovered[0] {
            LogEntry::OrderAdded(o) => assert_eq!(o.id, order.id),
            _ => panic!("Expected OrderAdded"),
        }

        drop(logger);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_trade_logger_recover_across_restarts() {
        let dir = std::env::temp_dir().join("test_trade_log_sled_restart");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).ok();

        let order = Order {
            id: [5u8; 32],
            trader: [6u8; 32],
            symbol: "BTC-USD".to_string(),
            side: OrderSide::Sell,
            price: 60000,
            amount: 1,
            signature: Vec::new(),
            nonce: 1,
            expiry: 0,
            settlement_preference: SettlementPreference::Standard,
            settlement_requester: SettlementRequester::Seller,
        };

        {
            let logger = TradeLogger::open(&dir).unwrap();
            logger.append(LogEntry::OrderAdded(order.clone())).unwrap();
        }

        {
            let logger = TradeLogger::open(&dir).unwrap();
            let recovered = logger.recover_all().unwrap();
            assert_eq!(recovered.len(), 1);
            match &recovered[0] {
                LogEntry::OrderAdded(o) => assert_eq!(o.price, 60000),
                _ => panic!("Expected OrderAdded"),
            }
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
