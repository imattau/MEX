use common::{OrderSide, SettlementPreference, SettlementRequester};
use engine::Match;
use orderlog::OrderReceipt;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitOrderRequest {
    pub trader: [u8; 32],
    pub symbol: String,
    pub side: OrderSide,
    pub price: u64,
    pub amount: u64,
    pub signature: Vec<u8>,
    pub nonce: u64,
    pub expiry: u64,
    #[serde(default)]
    pub settlement_preference: SettlementPreference,
    #[serde(default)]
    pub settlement_requester: SettlementRequester,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitOrderResponse {
    pub success: bool,
    pub order_id: [u8; 32],
    pub matches: Vec<Match>,
    pub error: Option<String>,
    // Independent, trader-verifiable proof of when this server received
    // the order -- see receipts.rs. None only when success is false
    // (rejected orders never entered the book, so there's nothing
    // ordering-sensitive to attest to).
    pub receipt: Option<OrderReceipt>,
    // Stage P2: true when order-sequencing (network-time-ordered
    // batching, see api::order_sequencing) is enabled and this order was
    // accepted but not yet applied -- `matches` is always empty in that
    // case, not because nothing matched, but because matching hasn't
    // happened yet. Real results arrive asynchronously over the
    // existing ws_broadcast websocket once this order's flush window
    // closes. Always false on the non-sequenced path (default,
    // unchanged): that path still applies and returns matches
    // synchronously, exactly as before this stage existed.
    pub pending: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriceLevel {
    pub price: u64,
    pub total_amount: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderBookResponse {
    pub symbol: String,
    pub bids: Vec<PriceLevel>,
    pub asks: Vec<PriceLevel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmCommitRequest {
    pub maker_order_id: [u8; 32],
    pub taker_order_id: [u8; 32],
    // The trade_hash the trader's own commitTrade call used -- trusted
    // opportunistically here, verified for real on-chain at settlement
    // time (see AppState::confirmed_trade_hashes's docs).
    pub trade_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmCommitResponse {
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRootResponse {
    pub root: [u8; 32],
    pub len: u64,
}
