use common::NodeId;
use engine::Match;
use std::collections::HashMap;

const RECENCY_WEIGHT: f64 = 0.7;
const MAX_REPORTS_PER_NODE: usize = 1000;

#[derive(Debug, Clone)]
pub enum TradeMetric {
    MatchFairness {
        slippage_bps: f64,
        suspicious: bool,
    },
    SettlementSpeed {
        actual_latency_secs: f64,
        expected_latency_secs: f64,
    },
    MatchSuccess,
    MatchFailure,
}

#[derive(Debug, Clone)]
pub struct TradeOutcome {
    pub trade_id: [u8; 32],
    pub node_id: NodeId,
    pub metrics: Vec<TradeMetric>,
    pub timestamp: f64,
    pub reporter_weight: f64,
}

pub struct ClientScoreAggregator {
    outcomes: HashMap<NodeId, Vec<TradeOutcome>>,
    trader_reputations: HashMap<[u8; 32], f64>,
    max_reports_per_node: usize,
}

impl Default for ClientScoreAggregator {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientScoreAggregator {
    pub fn new() -> Self {
        Self {
            outcomes: HashMap::new(),
            trader_reputations: HashMap::new(),
            max_reports_per_node: MAX_REPORTS_PER_NODE,
        }
    }

    pub fn record_trade_outcome(&mut self, outcome: TradeOutcome) {
        let entry = self.outcomes.entry(outcome.node_id).or_insert_with(Vec::new);
        entry.push(outcome);
        if entry.len() > self.max_reports_per_node {
            entry.remove(0);
        }
    }

    pub fn record_match_success(&mut self, node_id: NodeId, trade: &Match, timestamp: f64) {
        let outcome = TradeOutcome {
            trade_id: trade.maker_order_id,
            node_id,
            metrics: vec![
                TradeMetric::MatchSuccess,
                TradeMetric::MatchFairness {
                    slippage_bps: 0.0,
                    suspicious: false,
                },
                TradeMetric::SettlementSpeed {
                    actual_latency_secs: 0.0,
                    expected_latency_secs: trade.settlement_tier.deadline_seconds() as f64,
                },
            ],
            timestamp,
            reporter_weight: 1.0,
        };
        self.record_trade_outcome(outcome);
    }

    pub fn record_settlement_complete(
        &mut self,
        node_id: NodeId,
        trade_id: [u8; 32],
        actual_latency_secs: f64,
        expected_latency_secs: f64,
        timestamp: f64,
    ) {
        let outcome = TradeOutcome {
            trade_id,
            node_id,
            metrics: vec![TradeMetric::SettlementSpeed {
                actual_latency_secs,
                expected_latency_secs,
            }],
            timestamp,
            reporter_weight: 1.0,
        };
        self.record_trade_outcome(outcome);
    }

    pub fn record_dispute(
        &mut self,
        node_id: NodeId,
        trade_id: [u8; 32],
        slippage_bps: f64,
        timestamp: f64,
    ) {
        let outcome = TradeOutcome {
            trade_id,
            node_id,
            metrics: vec![
                TradeMetric::MatchFailure,
                TradeMetric::MatchFairness {
                    slippage_bps,
                    suspicious: true,
                },
            ],
            timestamp,
            reporter_weight: 1.0,
        };
        self.record_trade_outcome(outcome);
    }

    pub fn recompute_score(&self, node_id: NodeId) -> f64 {
        let outcomes = match self.outcomes.get(&node_id) {
            Some(o) => o,
            None => return 0.5,
        };

        if outcomes.is_empty() {
            return 0.5;
        }

        let mut weighted_sum = 0.0;
        let mut total_weight = 0.0;

        for (i, outcome) in outcomes.iter().enumerate() {
            let weight = RECENCY_WEIGHT.powf((outcomes.len() - i) as f64);
            let report_score = self.calculate_outcome_score(outcome);
            let effective = report_score * outcome.reporter_weight;

            weighted_sum += effective * weight;
            total_weight += weight;
        }

        if total_weight == 0.0 {
            return 0.5;
        }
        (weighted_sum / total_weight).clamp(0.0, 1.0)
    }

    fn calculate_outcome_score(&self, outcome: &TradeOutcome) -> f64 {
        let mut score = 0.0;
        let mut total_weight = 0.0;

        for metric in &outcome.metrics {
            let (metric_score, weight) = match metric {
                TradeMetric::MatchFairness { slippage_bps, suspicious } => {
                    if *suspicious {
                        (0.0, 0.3)
                    } else {
                        let n = 1.0 - (*slippage_bps / 10.0).clamp(0.0, 1.0);
                        (n, 0.2)
                    }
                }
                TradeMetric::SettlementSpeed { actual_latency_secs, expected_latency_secs } => {
                    if *expected_latency_secs == 0.0 {
                        (1.0, 0.3)
                    } else {
                        let ratio = actual_latency_secs / expected_latency_secs;
                        let n = if ratio <= 1.5 {
                            1.0 - ((ratio - 1.0) / 1.5).clamp(0.0, 1.0) * 0.5
                        } else {
                            0.0
                        };
                        (n, 0.3)
                    }
                }
                TradeMetric::MatchSuccess => (1.0, 0.3),
                TradeMetric::MatchFailure => (0.0, 0.3),
            };
            score += metric_score * weight;
            total_weight += weight;
        }

        if total_weight == 0.0 {
            return 0.5;
        }
        score / total_weight
    }

    pub fn update_trader_reputation(&mut self, trader: [u8; 32], delta: f64) {
        let entry = self.trader_reputations.entry(trader).or_insert(0.5);
        *entry = (*entry + delta).clamp(0.0, 1.0);
    }

    pub fn get_trader_reputation(&self, trader: &[u8; 32]) -> f64 {
        self.trader_reputations.get(trader).copied().unwrap_or(0.5)
    }

    pub fn penalize_trader(&mut self, trader: [u8; 32], penalty: f64) {
        let entry = self.trader_reputations.entry(trader).or_insert(0.5);
        *entry = (*entry - penalty).max(0.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{OrderSide, SettlementPreference, SettlementRequester};

    fn make_match(id_seed: u8, tier: SettlementPreference) -> Match {
        Match {
            maker_order_id: [id_seed; 32],
            taker_order_id: [id_seed + 1; 32],
            maker_trader: [1u8; 32],
            taker_trader: [2u8; 32],
            price: 100,
            amount: 10,
            timestamp_us: 0,
            settlement_tier: tier,
            fee_basis_points: tier.fee_basis_points(),
            seller: [2u8; 32],
            settlement_deadline: 0,
        }
    }

    #[test]
    fn test_new_node_gets_default_score() {
        let agg = ClientScoreAggregator::new();
        assert_eq!(agg.recompute_score(NodeId(1)), 0.5);
    }

    #[test]
    fn test_good_trades_increase_score() {
        let mut agg = ClientScoreAggregator::new();
        let trade = make_match(1, SettlementPreference::Standard);
        agg.record_match_success(NodeId(1), &trade, 1.0);
        agg.record_match_success(NodeId(1), &trade, 2.0);
        agg.record_match_success(NodeId(1), &trade, 3.0);
        let score = agg.recompute_score(NodeId(1));
        assert!(score > 0.7, "Expected > 0.7, got {}", score);
    }

    #[test]
    fn test_disputes_decrease_score() {
        let mut agg = ClientScoreAggregator::new();
        let trade = make_match(1, SettlementPreference::Standard);
        agg.record_match_success(NodeId(1), &trade, 1.0);
        agg.record_dispute(NodeId(1), [1; 32], 50.0, 2.0);
        let score = agg.recompute_score(NodeId(1));
        assert!(score < 0.6, "Expected < 0.6, got {}", score);
    }
}
