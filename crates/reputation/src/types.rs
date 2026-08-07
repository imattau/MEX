use common::NodeId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustLevel {
    Newcomer = 0,
    Contributor = 1,
    Trusted = 2,
    Elite = 3,
    Banned = 4,
}

impl TrustLevel {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Newcomer,
            1 => Self::Contributor,
            2 => Self::Trusted,
            3 => Self::Elite,
            _ => Self::Banned,
        }
    }

    pub fn max_order_rate(&self) -> u32 {
        match self {
            Self::Newcomer => 10,
            Self::Contributor => 100,
            Self::Trusted => u32::MAX,
            Self::Elite => u32::MAX,
            Self::Banned => 0,
        }
    }

    pub fn can_watchtower(&self) -> bool {
        matches!(self, Self::Contributor | Self::Trusted | Self::Elite)
    }

    pub fn can_tss(&self) -> bool {
        matches!(self, Self::Trusted | Self::Elite)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationState {
    pub node_id: NodeId,
    pub first_seen: f64,
    pub last_seen: f64,

    pub p2p_score: f64,
    pub client_score: f64,
    pub composite_score: f64,

    pub staked_amount: u64,
    pub vested_amount: u64,
    pub vesting_start: f64,
    pub vesting_period_secs: f64,

    pub id_change_count: u64,
    pub last_id_change: f64,
    pub uptime_percentage: f64,
    pub total_uptime_secs: f64,
    pub total_downtime_secs: f64,

    pub bonds: Vec<ReputationBond>,

    pub trust_level: TrustLevel,
    pub reputation_score: f64,
    pub reputation_multiplier: f64,

    pub dispute_history: Vec<DisputeRecord>,
    pub penalty_history: Vec<PenaltyRecord>,
    pub recovery_start: Option<f64>,
}

impl ReputationState {
    pub fn new(node_id: NodeId, now: f64) -> Self {
        Self {
            node_id,
            first_seen: now,
            last_seen: now,
            p2p_score: 0.5,
            client_score: 0.5,
            composite_score: 0.5,
            staked_amount: 0,
            vested_amount: 0,
            vesting_start: now,
            vesting_period_secs: 30.0 * 24.0 * 3600.0,
            id_change_count: 0,
            last_id_change: now,
            uptime_percentage: 0.0,
            total_uptime_secs: 0.0,
            total_downtime_secs: 0.0,
            bonds: Vec::new(),
            trust_level: TrustLevel::Newcomer,
            reputation_score: 0.0,
            reputation_multiplier: 1.0,
            dispute_history: Vec::new(),
            penalty_history: Vec::new(),
            recovery_start: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BondType {
    Watchtower,
    TSS,
    Settlement,
    Validator,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BondCondition {
    NoIDChange,
    Uptime90Percent,
    NoDisputesLost,
    ActiveWatchtower,
    SettlementOnTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationBond {
    pub bond_type: BondType,
    pub amount: u64,
    pub locked_until: f64,
    pub conditions: Vec<BondCondition>,
    pub forfeited: bool,
    pub forfeited_at: Option<f64>,
    pub forfeit_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisputeRecord {
    pub dispute_id: [u8; 32],
    pub disputer: NodeId,
    pub subject: NodeId,
    pub reason: String,
    pub resolved_at: f64,
    pub resolved_in_favor_of: NodeId,
    pub penalty_applied: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PenaltyType {
    ReputationPenalty(f64),
    StakePenalty(u64),
    BondForfeiture(BondType),
    Downgrade,
    TemporaryBan(f64),
    PermanentBan,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PenaltyRecord {
    pub penalty_type: PenaltyType,
    pub amount: u64,
    pub applied_at: f64,
    pub expires_at: f64,
    pub reason: String,
}

#[derive(Debug, Clone, Default)]
pub struct P2PMetrics {
    pub echo_rtt_ms: f64,
    pub heartbeat_miss_count: u32,
    pub censorship_flags: u32,
    pub flood_relay_count: u64,
    pub flood_drop_count: u64,
    pub last_heartbeat_time: f64,
    pub peer_verified: bool,
}
