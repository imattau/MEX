pub mod types;
pub mod p2p_score;
pub mod client_score;
pub mod composite;
pub mod stake;
pub mod integration;
pub mod metrics;

pub use types::*;
pub use p2p_score::{P2PScoreEngine, P2PScoreUpdate};
pub use client_score::{ClientScoreAggregator, TradeMetric, TradeOutcome};
pub use composite::ReputationEngine;
pub use stake::{SlashReason, StakeManager, VestingSchedule};
pub use integration::*;
pub use metrics::ReputationMetrics;
