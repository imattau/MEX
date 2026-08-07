use crate::types::{Match, OrderBook};
use common::{Order, OrderSide};
use std::collections::BTreeMap;

impl OrderBook {
    pub fn new(symbol: String) -> Self {
        Self {
            symbol,
            bids: BTreeMap::new(),
            asks: BTreeMap::new(),
        }
    }

    pub fn add_order(&mut self, mut order: Order) -> Vec<Match> {
        let mut matches = Vec::new();
        let timestamp_us = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

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

                        let match_amount = std::cmp::min(order.amount, maker_order.amount);
                        order.amount -= match_amount;
                        maker_order.amount -= match_amount;

                        matches.push(Match {
                            maker_order_id: maker_order.id,
                            taker_order_id: order.id,
                            price: ask_price,
                            amount: match_amount,
                            timestamp_us,
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

                            let match_amount = std::cmp::min(order.amount, maker_order.amount);
                            order.amount -= match_amount;
                            maker_order.amount -= match_amount;

                            matches.push(Match {
                                maker_order_id: maker_order.id,
                                taker_order_id: order.id,
                                price: bid_price,
                                amount: match_amount,
                                timestamp_us,
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
}
