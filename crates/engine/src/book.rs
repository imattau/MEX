use crate::types::{Match, OrderBook};
use common::{FeeCalculator, Order, OrderSide, SettlementPreference, SettlementRequester};
use std::collections::BTreeMap;

impl OrderBook {
    pub fn new(symbol: String) -> Self {
        Self {
            symbol,
            bids: BTreeMap::new(),
            asks: BTreeMap::new(),
            node_rewards: 0,
        }
    }

    pub fn add_order(&mut self, mut order: Order) -> Vec<Match> {
        if order.amount == 0 {
            return Vec::new();
        }
        if order.price == 0 || order.price > 1_000_000_000_000 {
            return Vec::new();
        }
        if order.amount as u128 * order.price as u128 > u64::MAX as u128 {
            return Vec::new();
        }

        let mut matches = Vec::new();
        let timestamp_us = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;
        let now_secs = timestamp_us / 1_000_000;

        match order.side {
            OrderSide::Buy => {
                let mut empty_levels = Vec::new();

                for (&ask_price, orders) in self.asks.iter_mut() {
                    if ask_price > order.price || order.amount == 0 {
                        break;
                    }

                    let mut filled_indices = Vec::new();
                    for (idx, maker_order) in orders.iter_mut().enumerate() {
                        if order.amount == 0 {
                            break;
                        }

                        if maker_order.trader == order.trader {
                            continue;
                        }

                        let match_amount = std::cmp::min(order.amount, maker_order.amount);
                        order.amount -= match_amount;
                        maker_order.amount -= match_amount;

                        let (tier, fee_bps, seller, fee_payer, deadline) =
                            Self::resolve_settlement_params(&order, maker_order, now_secs);

                        let fee = FeeCalculator::compute_fee_amount(
                            match_amount, ask_price, tier,
                        );
                        self.node_rewards += fee as u64;

                        matches.push(Match {
                            maker_order_id: maker_order.id,
                            taker_order_id: order.id,
                            maker_trader: maker_order.trader,
                            taker_trader: order.trader,
                            price: ask_price,
                            amount: match_amount,
                            timestamp_us,
                            settlement_tier: tier,
                            fee_basis_points: fee_bps,
                            seller,
                            fee_payer,
                            settlement_deadline: deadline,
                        });

                        tracing::info!(
                            symbol = %self.symbol,
                            maker_id = ?maker_order.id,
                            taker_id = ?order.id,
                            price = ask_price,
                            amount = match_amount,
                            "Order matched successfully"
                        );

                        if maker_order.amount == 0 {
                            filled_indices.push(idx);
                        }
                    }

                    for idx in filled_indices.into_iter().rev() {
                        orders.remove(idx);
                    }

                    if orders.is_empty() {
                        empty_levels.push(ask_price);
                    }
                }

                for price in empty_levels {
                    self.asks.remove(&price);
                }

                if order.amount > 0 {
                    tracing::debug!(symbol = %self.symbol, price = order.price, amount = order.amount, "Adding remaining buy order to book");
                    self.bids.entry(order.price).or_default().push(order);
                }
            }
            OrderSide::Sell => {
                let mut empty_levels = Vec::new();

                let matching_prices: Vec<u64> = self
                    .bids
                    .keys()
                    .rev()
                    .copied()
                    .take_while(|&bid_price| bid_price >= order.price)
                    .collect();

                for bid_price in matching_prices {
                    if order.amount == 0 {
                        break;
                    }

                    if let Some(orders) = self.bids.get_mut(&bid_price) {
                        let mut filled_indices = Vec::new();
                        for (idx, maker_order) in orders.iter_mut().enumerate() {
                            if order.amount == 0 {
                                break;
                            }

                            if maker_order.trader == order.trader {
                                continue;
                            }

                            let match_amount = std::cmp::min(order.amount, maker_order.amount);
                            order.amount -= match_amount;
                            maker_order.amount -= match_amount;

                            let (tier, fee_bps, seller, fee_payer, deadline) =
                                Self::resolve_settlement_params(&order, maker_order, now_secs);

                            let fee = FeeCalculator::compute_fee_amount(
                                match_amount, bid_price, tier,
                            );
                            self.node_rewards += fee as u64;

                            matches.push(Match {
                                maker_order_id: maker_order.id,
                                taker_order_id: order.id,
                                maker_trader: maker_order.trader,
                                taker_trader: order.trader,
                                price: bid_price,
                                amount: match_amount,
                                timestamp_us,
                                settlement_tier: tier,
                                fee_basis_points: fee_bps,
                                seller,
                                fee_payer,
                                settlement_deadline: deadline,
                            });

                            if maker_order.amount == 0 {
                                filled_indices.push(idx);
                            }
                        }

                        for idx in filled_indices.into_iter().rev() {
                            orders.remove(idx);
                        }

                        if orders.is_empty() {
                            empty_levels.push(bid_price);
                        }
                    }
                }

                for price in empty_levels {
                    self.bids.remove(&price);
                }

                if order.amount > 0 {
                    self.asks.entry(order.price).or_default().push(order);
                }
            }
        }

        matches
    }

    fn resolve_settlement_params(
        taker_order: &Order,
        maker_order: &Order,
        now_secs: u64,
    ) -> (SettlementPreference, u32, [u8; 32], [u8; 32], u64) {
        let sell_order = if taker_order.side == OrderSide::Sell {
            taker_order
        } else {
            maker_order
        };

        let buy_order = if taker_order.side == OrderSide::Buy {
            taker_order
        } else {
            maker_order
        };

        let (tier, fee_payer) = match &sell_order.settlement_requester {
            SettlementRequester::Buyer => {
                (buy_order.settlement_preference, buy_order.trader)
            }
            SettlementRequester::Seller => {
                (sell_order.settlement_preference, sell_order.trader)
            }
        };

        let fee_bps = tier.fee_basis_points();
        let deadline = now_secs + tier.deadline_seconds();

        (tier, fee_bps, sell_order.trader, fee_payer, deadline)
    }

    pub fn cancel_order(&mut self, order_id: [u8; 32]) -> bool {
        for orders in self.bids.values_mut() {
            if let Some(pos) = orders.iter().position(|o| o.id == order_id) {
                orders.remove(pos);
                return true;
            }
        }
        for orders in self.asks.values_mut() {
            if let Some(pos) = orders.iter().position(|o| o.id == order_id) {
                orders.remove(pos);
                return true;
            }
        }
        false
    }
}
