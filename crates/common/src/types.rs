use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Region {
    UsEast1,
    EuWest1,
    ApSoutheast1,
}

impl Region {
    pub fn name(&self) -> &'static str {
        match self {
            Region::UsEast1 => "us-east-1",
            Region::EuWest1 => "eu-west-1",
            Region::ApSoutheast1 => "ap-southeast-1",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderSide {
    Buy,
    Sell,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SettlementPreference {
    Standard,
    Express,
    Instant,
}

impl Default for SettlementPreference {
    fn default() -> Self {
        Self::Standard
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SettlementRequester {
    Seller,
    Buyer,
}

impl Default for SettlementRequester {
    fn default() -> Self {
        Self::Seller
    }
}

impl SettlementPreference {
    pub fn fee_basis_points(&self) -> u32 {
        match self {
            SettlementPreference::Standard => 5,
            SettlementPreference::Express => 15,
            SettlementPreference::Instant => 50,
        }
    }

    pub fn deadline_seconds(&self) -> u64 {
        match self {
            SettlementPreference::Standard => 86_400,
            SettlementPreference::Express => 600,
            SettlementPreference::Instant => 60,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Order {
    pub id: [u8; 32],
    pub trader: [u8; 32],
    pub symbol: String,
    pub side: OrderSide,
    pub price: u64,
    pub amount: u64,
    pub signature: Vec<u8>,
    pub nonce: u64,
    pub expiry: u64,
    pub settlement_preference: SettlementPreference,
    pub settlement_requester: SettlementRequester,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FloodMessage {
    pub order: Order,
    pub hop_count: u8,
    pub path: Vec<NodeId>,
    pub timestamp: f64,
    pub source_region: Region,
}
