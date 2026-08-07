use common::Order;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

pub struct TraderMemoryRegion {
    pub trader_id: [u8; 32],
    pub buffer: Vec<u8>,
    pub rkey: u32,
}

impl TraderMemoryRegion {
    pub fn new(trader_id: [u8; 32], size: usize, rkey: u32) -> Self {
        Self {
            trader_id,
            buffer: vec![0; size],
            rkey,
        }
    }

    pub fn write_orders(&mut self, orders: &[Order]) -> Result<(), String> {
        let serialized = serde_json::to_vec(orders).map_err(|e| e.to_string())?;
        if serialized.len() > self.buffer.len() {
            return Err("Data exceeds memory region size".to_string());
        }
        // Write size prefix
        let len_bytes = (serialized.len() as u32).to_be_bytes();
        self.buffer[0..4].copy_from_slice(&len_bytes);
        self.buffer[4..4 + serialized.len()].copy_from_slice(&serialized);
        Ok(())
    }

    pub fn read_orders(&self) -> Result<Vec<Order>, String> {
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&self.buffer[0..4]);
        let len = u32::from_be_bytes(len_bytes) as usize;
        if len == 0 {
            return Ok(Vec::new());
        }
        if len + 4 > self.buffer.len() {
            return Err("Invalid size prefix".to_string());
        }
        let orders: Vec<Order> = serde_json::from_slice(&self.buffer[4..4 + len])
            .map_err(|e| e.to_string())?;
        Ok(orders)
    }
}

pub struct MockRdmaConnection {
    pub address: String,
    pub rkey: u32,
}

pub struct TraderMemoryRegionManager {
    pub regions: HashMap<[u8; 32], TraderMemoryRegion>,
}

impl TraderMemoryRegionManager {
    pub fn new() -> Self {
        Self {
            regions: HashMap::new(),
        }
    }

    pub fn register(&mut self, trader_id: [u8; 32], size: usize, rkey: u32) {
        let mr = TraderMemoryRegion::new(trader_id, size, rkey);
        self.regions.insert(trader_id, mr);
    }

    pub fn get_region_mut(&mut self, trader_id: &[u8; 32]) -> Option<&mut TraderMemoryRegion> {
        self.regions.get_mut(trader_id)
    }
}

pub struct PullScheduler {
    pub active_traders: VecDeque<[u8; 32]>,
    pub last_pull: Instant,
    pub pull_interval: Duration,
}

impl PullScheduler {
    pub fn new(pull_interval_us: u64) -> Self {
        Self {
            active_traders: VecDeque::new(),
            last_pull: Instant::now(),
            pull_interval: Duration::from_micros(pull_interval_us),
        }
    }

    pub fn add_trader(&mut self, trader_id: [u8; 32]) {
        if !self.active_traders.contains(&trader_id) {
            self.active_traders.push_back(trader_id);
        }
    }

    pub fn remove_trader(&mut self, trader_id: &[u8; 32]) {
        self.active_traders.retain(|id| id != trader_id);
    }

    pub fn should_pull(&self) -> bool {
        self.last_pull.elapsed() >= self.pull_interval
    }

    pub fn perform_pull(
        &mut self,
        manager: &TraderMemoryRegionManager,
    ) -> (Vec<Order>, Option<Duration>) {
        let start = Instant::now();
        let mut pulled_orders = Vec::new();

        // High-frequency pulling: pull from the next trader in round-robin fashion
        if let Some(trader_id) = self.active_traders.pop_front() {
            if let Some(region) = manager.regions.get(&trader_id) {
                if let Ok(orders) = region.read_orders() {
                    pulled_orders.extend(orders);
                }
            }
            // Put trader back to the end of queue
            self.active_traders.push_back(trader_id);
        }

        self.last_pull = Instant::now();
        let elapsed = start.elapsed();
        (pulled_orders, Some(elapsed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::OrderSide;

    fn create_test_order(id: u8) -> Order {
        let mut order_id = [0u8; 32];
        order_id[0] = id;
        Order {
            id: order_id,
            trader: [0u8; 32],
            symbol: "ETH-USD".to_string(),
            side: OrderSide::Buy,
            price: 3000,
            amount: 5,
            signature: Vec::new(),
            nonce: id as u64,
            expiry: 0,
        }
    }

    #[test]
    fn test_memory_region_write_read() {
        let trader_id = [1u8; 32];
        let mut region = TraderMemoryRegion::new(trader_id, 1024, 999);
        
        let orders = vec![create_test_order(1), create_test_order(2)];
        region.write_orders(&orders).unwrap();

        let read_orders = region.read_orders().unwrap();
        assert_eq!(read_orders.len(), 2);
        assert_eq!(read_orders[0].nonce, 1);
        assert_eq!(read_orders[1].nonce, 2);
    }

    #[test]
    fn test_scheduler_round_robin() {
        let mut manager = TraderMemoryRegionManager::new();
        let trader_a = [1u8; 32];
        let trader_b = [2u8; 32];

        manager.register(trader_a, 1024, 100);
        manager.register(trader_b, 1024, 200);

        let mut scheduler = PullScheduler::new(100); // 100us
        scheduler.add_trader(trader_a);
        scheduler.add_trader(trader_b);

        // Write order for A
        manager.get_region_mut(&trader_a).unwrap().write_orders(&[create_test_order(10)]).unwrap();

        // First pull should get Trader A's orders
        let (orders_a, _) = scheduler.perform_pull(&manager);
        assert_eq!(orders_a.len(), 1);
        assert_eq!(orders_a[0].nonce, 10);

        // Second pull should check Trader B (empty)
        let (orders_b, _) = scheduler.perform_pull(&manager);
        assert!(orders_b.is_empty());
    }
}
