use crate::state::SimulationState;
use common::{Order, OrderSide};
use rand::Rng;

pub struct StepEngine {
    noise_amplitude: f64,
}

impl StepEngine {
    pub fn new(noise_amplitude: f64) -> Self {
        Self { noise_amplitude }
    }

    pub fn inject_noise(&self, state: &mut SimulationState) {
        let mut rng = rand::thread_rng();
        let noise_order_count = rng.gen_range(1..4);

        for _ in 0..noise_order_count {
            let mid = state.mid_price().unwrap_or(3000.0);
            let noise_price =
                (mid * (1.0 + rng.gen_range(-self.noise_amplitude..self.noise_amplitude))) as u64;
            let noise_price = noise_price.max(1);

            let amt = rng.gen_range(1..20);
            let side = if rng.gen_bool(0.5) {
                OrderSide::Buy
            } else {
                OrderSide::Sell
            };

            let mut noise_trader = [0u8; 32];
            rng.fill(&mut noise_trader);
            let mut order_id_bytes = [0u8; 32];
            rng.fill(&mut order_id_bytes);

            let order = Order {
                id: order_id_bytes,
                trader: noise_trader,
                symbol: state.book.symbol.clone(),
                side,
                price: noise_price,
                amount: amt,
                signature: Vec::new(),
                nonce: state.step_number * 100 + noise_order_count as u64,
                expiry: 1000000,
                settlement_preference: common::SettlementPreference::Standard,
                settlement_requester: common::SettlementRequester::Seller,
            };

            let matches = state.book.add_order(order);
            state.matches_buffer.extend(matches);
        }
    }
}
