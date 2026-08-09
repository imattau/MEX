// Accountability for the off-chain matching engine's order sequencing.
// crates/engine's OrderBook is a plain in-memory BTreeMap with no
// independent record of when an order actually arrived -- nothing stops
// the operator from reordering or delaying orders before matching them,
// and (without this crate) there'd be no way for anyone to even detect
// it after the fact. This crate provides two pieces:
//
//   1. OrderReceipt -- a signed, timestamped proof of when an order was
//      received, signed BEFORE matching happens (see sign_receipt).
//   2. HashChainLog<T> -- an append-only, tamper-evident log (any
//      rewrite of a past entry breaks every hash after it) that the
//      order-receiving server appends every OrderReceipt to, and can
//      also use to log the Matches it actually produced. A third party
//      can fetch both logs, verify the hash chains, replay correct
//      price-time-priority matching against the order log using
//      engine::OrderBook directly, and diff that against what the
//      server actually reported via the match log -- divergence is
//      provable misconduct.
//
// This alone does not PREVENT front-running/reordering -- it makes it
// detectable and provable after the fact, which is the same "trust but
// verify, then punish" model this codebase already uses for settlement
// deadlines (see NodeRegistry.slashNode / claimSlash).

use common::{OrderSide, SettlementPreference, SettlementRequester};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderReceipt {
    pub order_id: [u8; 32],
    pub trader: [u8; 32],
    pub symbol: String,
    pub side: OrderSide,
    pub price: u64,
    pub amount: u64,
    pub nonce: u64,
    pub expiry: u64,
    // Both needed (alongside price/amount/side) for an auditor to
    // reconstruct fee_basis_points/settlement_deadline/fee_payer the same
    // way engine::book::resolve_settlement_params would, so a replayed
    // Match can be compared field-for-field against what the server
    // actually reported in match_log, not just approximately.
    pub settlement_preference: SettlementPreference,
    pub settlement_requester: SettlementRequester,
    // Wall-clock microseconds when this server received the order, set by
    // sign_receipt itself (never caller-supplied) -- signing happens
    // before matching runs, so this timestamp can't be chosen to fit
    // whatever match order already happened.
    pub received_at_us: u64,
    pub node_pubkey: [u8; 32],
    pub signature: Vec<u8>,
}

// Canonical byte layout signed over -- fixed-width fields plus order_id/
// trader (both already 32 bytes) give unambiguous field boundaries without
// needing a length prefix on `symbol`, matching the convention already
// used for off-chain order signatures elsewhere in this codebase (see
// trader-client's serialize_order_message).
#[allow(clippy::too_many_arguments)]
fn receipt_message(
    order_id: [u8; 32],
    trader: [u8; 32],
    symbol: &str,
    side: OrderSide,
    price: u64,
    amount: u64,
    nonce: u64,
    expiry: u64,
    settlement_preference: SettlementPreference,
    settlement_requester: SettlementRequester,
    received_at_us: u64,
) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&order_id);
    msg.extend_from_slice(&trader);
    msg.extend_from_slice(symbol.as_bytes());
    msg.push(match side {
        OrderSide::Buy => 0u8,
        OrderSide::Sell => 1u8,
    });
    msg.extend_from_slice(&price.to_be_bytes());
    msg.extend_from_slice(&amount.to_be_bytes());
    msg.extend_from_slice(&nonce.to_be_bytes());
    msg.extend_from_slice(&expiry.to_be_bytes());
    msg.push(match settlement_preference {
        SettlementPreference::Standard => 0u8,
        SettlementPreference::Express => 1u8,
        SettlementPreference::Instant => 2u8,
    });
    msg.push(match settlement_requester {
        SettlementRequester::Seller => 0u8,
        SettlementRequester::Buyer => 1u8,
    });
    msg.extend_from_slice(&received_at_us.to_be_bytes());
    msg
}

#[allow(clippy::too_many_arguments)]
pub fn sign_receipt(
    signing_key: &SigningKey,
    order_id: [u8; 32],
    trader: [u8; 32],
    symbol: &str,
    side: OrderSide,
    price: u64,
    amount: u64,
    nonce: u64,
    expiry: u64,
    settlement_preference: SettlementPreference,
    settlement_requester: SettlementRequester,
) -> OrderReceipt {
    let received_at_us = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64;

    let msg = receipt_message(
        order_id,
        trader,
        symbol,
        side,
        price,
        amount,
        nonce,
        expiry,
        settlement_preference,
        settlement_requester,
        received_at_us,
    );
    let signature = signing_key.sign(&msg);

    OrderReceipt {
        order_id,
        trader,
        symbol: symbol.to_string(),
        side,
        price,
        amount,
        nonce,
        expiry,
        settlement_preference,
        settlement_requester,
        received_at_us,
        node_pubkey: signing_key.verifying_key().to_bytes(),
        signature: signature.to_bytes().to_vec(),
    }
}

// Independent of this server -- a trader (or third-party auditor) verifies
// a receipt entirely from its own fields plus the node's known pubkey,
// with no need to trust or query this server again.
pub fn verify_receipt(receipt: &OrderReceipt) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(&receipt.node_pubkey) else {
        return false;
    };
    let Ok(sig_bytes) = <[u8; 64]>::try_from(receipt.signature.as_slice()) else {
        return false;
    };
    let signature = Signature::from_bytes(&sig_bytes);
    let msg = receipt_message(
        receipt.order_id,
        receipt.trader,
        &receipt.symbol,
        receipt.side,
        receipt.price,
        receipt.amount,
        receipt.nonce,
        receipt.expiry,
        receipt.settlement_preference,
        receipt.settlement_requester,
        receipt.received_at_us,
    );
    verifying_key.verify(&msg, &signature).is_ok()
}

// One entry in an append-only hash chain: entry_hash commits to
// (prev_hash, seq, payload), so rewriting any past entry -- including
// deleting or reordering one -- changes every entry_hash from that point
// forward. Generic over payload type so the same log mechanism serves
// both the order log (T = OrderReceipt) and the match log (T =
// engine::Match) the auditor diffs against each other.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry<T> {
    pub seq: u64,
    pub prev_hash: [u8; 32],
    pub entry_hash: [u8; 32],
    pub payload: T,
}

fn compute_entry_hash<T: Serialize>(seq: u64, prev_hash: [u8; 32], payload: &T) -> [u8; 32] {
    // serde_json::to_vec is deterministic for a fixed struct shape (field
    // order follows declaration order, not a HashMap) -- sufficient here
    // since every payload type this log carries (OrderReceipt, Match) is
    // a plain struct, not a map with nondeterministic key order.
    let payload_bytes = serde_json::to_vec(payload).expect("log payload must serialize");
    let mut hasher = Sha256::new();
    hasher.update(seq.to_be_bytes());
    hasher.update(prev_hash);
    hasher.update(&payload_bytes);
    hasher.finalize().into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashChainLog<T> {
    // Stage P4-6b: the seq of the earliest entry THIS instance is
    // responsible for, and the chain root immediately before it. A
    // genesis log (the only kind before this stage existed) always has
    // base_seq=0, base_prev_hash=[0u8;32] -- see Default. A "hot window"
    // log resuming after an archived prefix (see resume_from) has both
    // set to wherever the archive left off, so append/root/
    // entries_since/try_append_remote all behave exactly as if the
    // archived entries were still physically present in `entries`,
    // without this log ever needing to hold them.
    base_seq: u64,
    base_prev_hash: [u8; 32],
    entries: Vec<LogEntry<T>>,
}

impl<T> Default for HashChainLog<T> {
    fn default() -> Self {
        Self {
            base_seq: 0,
            base_prev_hash: [0u8; 32],
            entries: Vec::new(),
        }
    }
}

impl<T: Serialize + Clone> HashChainLog<T> {
    pub fn new() -> Self {
        Self::default()
    }

    // Stage P4-6b: a log that picks up mid-chain, after everything
    // before `next_seq` has been moved to archival storage. `prev_root`
    // must be the entry_hash of whatever entry immediately precedes
    // `next_seq` in the real, full history -- verify_chain_segment
    // confirming the archived prefix is valid already gives you this as
    // that prefix's own last entry_hash (or [0u8;32] if archiving
    // nothing yet, i.e. next_seq=0). Getting `prev_root` wrong silently
    // produces a log that looks internally self-consistent to THIS
    // process but would fail verify_chain_segment against the real
    // archived prefix -- there's no way to detect that mistake from
    // inside this log alone, so callers (Stage P4-6c's archival step)
    // must derive it from the archive itself, never guess or reuse a
    // stale value.
    pub fn resume_from(next_seq: u64, prev_root: [u8; 32]) -> Self {
        Self {
            base_seq: next_seq,
            base_prev_hash: prev_root,
            entries: Vec::new(),
        }
    }

    pub fn append(&mut self, payload: T) -> &LogEntry<T> {
        let seq = self.next_seq();
        let prev_hash = self
            .entries
            .last()
            .map(|e| e.entry_hash)
            .unwrap_or(self.base_prev_hash);
        let entry_hash = compute_entry_hash(seq, prev_hash, &payload);
        self.entries.push(LogEntry {
            seq,
            prev_hash,
            entry_hash,
            payload,
        });
        self.entries.last().unwrap()
    }

    pub fn root(&self) -> [u8; 32] {
        self.entries
            .last()
            .map(|e| e.entry_hash)
            .unwrap_or(self.base_prev_hash)
    }

    // Number of entries THIS instance physically holds -- NOT the
    // absolute seq of its last entry once base_seq is nonzero (a hot
    // window resumed at seq 1000 with 3 entries has len() == 3, not
    // 1003). Use next_seq() for the absolute count of everything up to
    // and including this log, archived prefix included.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    // The absolute seq this log will assign to its NEXT appended entry
    // -- equivalently, base_seq + how many entries it already holds.
    // For a genesis log this is identical to len(); Stage P4-6c's
    // archival step uses this (not len()) to know where to resume a
    // fresh hot window from after moving this log's current contents to
    // cold storage.
    pub fn next_seq(&self) -> u64 {
        self.base_seq + self.entries.len() as u64
    }

    pub fn entries(&self) -> &[LogEntry<T>] {
        &self.entries
    }

    // `seq` is an ABSOLUTE seq (matching entry.seq, not a local index
    // into this instance's own `entries`) -- correct for both a genesis
    // log (where the two coincide) and a resumed hot window (where they
    // don't). A `seq` older than this log's own base_seq -- i.e.
    // already-archived history this instance never held -- clamps to
    // the start of what it DOES have, same as an out-of-range seq
    // always has (this method has never had a way to signal "some of
    // what you asked for isn't here"; Stage P4-6d's fetch-API work is
    // where that gets handled, by consulting the archive too).
    pub fn entries_since(&self, seq: u64) -> &[LogEntry<T>] {
        let start = seq
            .saturating_sub(self.base_seq)
            .min(self.entries.len() as u64) as usize;
        &self.entries[start..]
    }

    // Accepts an entry that arrived from elsewhere (e.g. broadcast over
    // the mesh) into this log as its next entry, IF it actually is a
    // valid extension of what's here already -- same check
    // verify_chain does for a whole slice, applied one entry at a time
    // as each arrives, so a mirror doesn't have to buffer everything and
    // re-verify from scratch on every new entry. Rejects (returning
    // Err, entry untouched) a wrong seq, a prev_hash that doesn't match
    // this log's current root, or a claimed entry_hash that doesn't
    // actually match its own seq/prev_hash/payload -- any of which means
    // either the sender is lying or this mirror missed an earlier entry
    // and needs to resync (see entries_since for catching back up).
    pub fn try_append_remote(&mut self, entry: LogEntry<T>) -> Result<(), String> {
        if !verify_next_entry(self.root(), self.next_seq(), &entry) {
            return Err(format!(
                "entry seq={} does not validly extend this log (current root {}, next expected seq {})",
                entry.seq,
                hex_prefix(&self.root()),
                self.next_seq()
            ));
        }
        self.entries.push(entry);
        Ok(())
    }
}

// Stage P4-6a: the general form verify_chain (below) is a special case
// of -- confirms `entries` is an internally consistent, contiguous
// continuation of a chain whose next expected sequence number is
// `start_seq` and whose root (prev_hash for that next entry) is
// `start_prev_hash`, WITHOUT needing anything before `start_seq` in
// memory at all. This is what makes an archived prefix + a live "hot
// window" independently verifiable as two separate calls whose results
// compose: verify_chain_segment(0, [0;32], archived_prefix) confirms
// the archive, verify_chain_segment(archived_prefix.len(), archived_
// prefix.last().entry_hash, hot_window) confirms the hot window
// genuinely continues it -- an auditor never needs the whole history
// loaded at once to be convinced no entry anywhere was inserted,
// deleted, or reordered.
pub fn verify_chain_segment<T: Serialize + Clone>(
    start_seq: u64,
    start_prev_hash: [u8; 32],
    entries: &[LogEntry<T>],
) -> bool {
    let mut prev_hash = start_prev_hash;
    for (i, entry) in entries.iter().enumerate() {
        let Some(expected_seq) = start_seq.checked_add(i as u64) else {
            return false;
        };
        if entry.seq != expected_seq {
            return false;
        }
        if entry.prev_hash != prev_hash {
            return false;
        }
        let expected_hash = compute_entry_hash(entry.seq, entry.prev_hash, &entry.payload);
        if expected_hash != entry.entry_hash {
            return false;
        }
        prev_hash = entry.entry_hash;
    }
    true
}

// Recomputes the hash chain over `entries` from scratch, starting at the
// genesis position (seq 0, the zero prev_hash HashChainLog::new's first
// append always uses) -- this is what makes the log auditable by
// someone who doesn't trust the server that served it: if this returns
// true, no entry could have been inserted, deleted, or reordered after
// the fact without detection, regardless of who's asking. The special
// case of verify_chain_segment where the caller holds the ENTIRE
// history, not just some later continuation of it -- see that
// function's own docs for verifying an archived-and-truncated log
// without needing everything in memory at once.
pub fn verify_chain<T: Serialize + Clone>(entries: &[LogEntry<T>]) -> bool {
    verify_chain_segment(0, [0u8; 32], entries)
}

// The single-entry version of verify_chain's check: does `entry` validly
// extend a log whose current root is `current_root` and whose next
// expected sequence number is `expected_seq`? Used by
// HashChainLog::try_append_remote for a mirror that verifies each entry
// as it arrives instead of re-checking the whole chain from scratch.
pub fn verify_next_entry<T: Serialize>(
    current_root: [u8; 32],
    expected_seq: u64,
    entry: &LogEntry<T>,
) -> bool {
    entry.seq == expected_seq
        && entry.prev_hash == current_root
        && entry.entry_hash == compute_entry_hash(entry.seq, entry.prev_hash, &entry.payload)
}

fn hex_prefix(bytes: &[u8; 32]) -> String {
    bytes.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let receipt = sign_receipt(
            &signing_key,
            [1u8; 32],
            [2u8; 32],
            "ETH-USD",
            OrderSide::Buy,
            3000,
            1,
            42,
            9999,
            SettlementPreference::Standard,
            SettlementRequester::Seller,
        );
        assert!(verify_receipt(&receipt));
    }

    #[test]
    fn test_tampered_receipt_fails_verification() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let mut receipt = sign_receipt(
            &signing_key,
            [1u8; 32],
            [2u8; 32],
            "ETH-USD",
            OrderSide::Buy,
            3000,
            1,
            42,
            9999,
            SettlementPreference::Standard,
            SettlementRequester::Seller,
        );
        receipt.price = 4000;
        assert!(!verify_receipt(&receipt));
    }

    #[test]
    fn test_wrong_key_fails_verification() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let other_key = SigningKey::generate(&mut OsRng);
        let mut receipt = sign_receipt(
            &signing_key,
            [1u8; 32],
            [2u8; 32],
            "ETH-USD",
            OrderSide::Buy,
            3000,
            1,
            42,
            9999,
            SettlementPreference::Standard,
            SettlementRequester::Seller,
        );
        receipt.node_pubkey = other_key.verifying_key().to_bytes();
        assert!(!verify_receipt(&receipt));
    }

    #[test]
    fn test_hash_chain_links_entries() {
        let mut log: HashChainLog<u64> = HashChainLog::new();
        log.append(1);
        log.append(2);
        log.append(3);
        assert_eq!(log.len(), 3);
        assert!(verify_chain(log.entries()));
        assert_eq!(log.entries()[1].prev_hash, log.entries()[0].entry_hash);
        assert_eq!(log.entries()[2].prev_hash, log.entries()[1].entry_hash);
        assert_eq!(log.root(), log.entries()[2].entry_hash);
    }

    // Stage P4-6a: the actual point of verify_chain_segment -- splitting
    // a log into an "archived" prefix and a "hot" suffix, verifying each
    // independently (neither call ever sees the other half), and
    // confirming they compose into the same trust guarantee whole-log
    // verify_chain would have given.
    #[test]
    fn test_verify_chain_segment_composes_across_an_archived_boundary() {
        let mut log: HashChainLog<u64> = HashChainLog::new();
        for i in 0..6u64 {
            log.append(i);
        }
        let all = log.entries();
        let (archived, hot) = all.split_at(3);

        // The archived prefix alone verifies exactly like a whole,
        // self-contained log would (genesis start).
        assert!(verify_chain_segment(0, [0u8; 32], archived));

        // The hot suffix, in isolation, is NOT verifiable against
        // genesis -- it doesn't start at seq 0.
        assert!(!verify_chain_segment(0, [0u8; 32], hot));

        // But it DOES verify as a continuation from exactly where the
        // archived prefix left off.
        let boundary_root = archived.last().unwrap().entry_hash;
        assert!(verify_chain_segment(3, boundary_root, hot));

        // A wrong boundary root (as if the archive had been tampered
        // with, or the wrong checkpoint was used) must be rejected.
        assert!(!verify_chain_segment(3, [0xFFu8; 32], hot));
    }

    #[test]
    fn test_verify_chain_segment_matches_verify_chain_for_a_full_genesis_log() {
        let mut log: HashChainLog<u64> = HashChainLog::new();
        log.append(10);
        log.append(20);
        assert!(verify_chain_segment(0, [0u8; 32], log.entries()));
        assert_eq!(
            verify_chain_segment(0, [0u8; 32], log.entries()),
            verify_chain(log.entries())
        );
    }

    #[test]
    fn test_verify_chain_segment_still_catches_tampering_within_a_segment() {
        let mut log: HashChainLog<u64> = HashChainLog::new();
        for i in 0..6u64 {
            log.append(i);
        }
        let all = log.entries();
        let (archived, hot) = all.split_at(3);
        let boundary_root = archived.last().unwrap().entry_hash;

        let mut tampered_hot = hot.to_vec();
        tampered_hot[0].payload = 999;
        assert!(!verify_chain_segment(3, boundary_root, &tampered_hot));
    }

    #[test]
    fn test_tampered_entry_breaks_chain_verification() {
        let mut log: HashChainLog<u64> = HashChainLog::new();
        log.append(1);
        log.append(2);
        log.append(3);
        let mut entries = log.entries().to_vec();
        entries[1].payload = 999; // operator tries to rewrite a past order after the fact
        assert!(!verify_chain(&entries));
    }

    #[test]
    fn test_deleted_entry_breaks_chain_verification() {
        let mut log: HashChainLog<u64> = HashChainLog::new();
        log.append(1);
        log.append(2);
        log.append(3);
        let mut entries = log.entries().to_vec();
        entries.remove(1); // operator tries to silently drop an order from the record
        assert!(!verify_chain(&entries));
    }

    #[test]
    fn test_reordered_entries_break_chain_verification() {
        let mut log: HashChainLog<u64> = HashChainLog::new();
        log.append(1);
        log.append(2);
        log.append(3);
        let mut entries = log.entries().to_vec();
        entries.swap(0, 1); // operator tries to claim a different arrival order
        assert!(!verify_chain(&entries));
    }

    #[test]
    fn test_entries_since() {
        let mut log: HashChainLog<u64> = HashChainLog::new();
        for i in 0..5 {
            log.append(i);
        }
        assert_eq!(log.entries_since(3).len(), 2);
        assert_eq!(log.entries_since(0).len(), 5);
        assert_eq!(log.entries_since(100).len(), 0);
    }

    // Stage P4-6b: the actual point of resume_from -- a hot window
    // picking up after an archived prefix must produce a chain that's
    // indistinguishable, verification-wise, from one continuous log
    // that never had anything moved out of it. Splits a real 6-entry
    // log the same way the P4-6a test does, builds a resumed log from
    // ONLY the hot half, appends more to it, and confirms the combined
    // (archived_prefix ++ hot_window.entries()) verifies as one
    // unbroken segment continuation from genesis.
    #[test]
    fn test_resume_from_produces_a_chain_that_validly_continues_the_archived_prefix() {
        let mut original: HashChainLog<u64> = HashChainLog::new();
        for i in 0..6u64 {
            original.append(i);
        }
        let all = original.entries().to_vec();
        let (archived, hot_before_archiving) = all.split_at(3);
        let boundary_root = archived.last().unwrap().entry_hash;

        let mut hot = HashChainLog::resume_from(3, boundary_root);
        // Re-append the same payloads a real archival step would have
        // left behind in the fresh hot window.
        for entry in hot_before_archiving {
            hot.append(entry.payload);
        }
        // And some genuinely new entries, arriving after the archive
        // point, to prove ongoing appends keep working correctly too.
        hot.append(100);
        hot.append(200);

        assert_eq!(
            hot.next_seq(),
            8,
            "next_seq must account for the archived prefix's length too"
        );
        assert_eq!(
            hot.len(),
            5,
            "len() only counts what THIS instance physically holds"
        );

        // The resumed log's own entries verify as a continuation...
        assert!(verify_chain_segment(3, boundary_root, hot.entries()));
        // ...and the archived prefix plus the resumed log's entries
        // together verify as a single, unbroken chain from genesis --
        // exactly what a full, non-archived log's entries() would have
        // produced.
        let mut combined = archived.to_vec();
        combined.extend_from_slice(hot.entries());
        assert!(verify_chain(&combined));
    }

    #[test]
    fn test_resume_from_with_genesis_values_behaves_like_new() {
        let mut resumed: HashChainLog<u64> = HashChainLog::resume_from(0, [0u8; 32]);
        resumed.append(1);
        resumed.append(2);

        let mut fresh: HashChainLog<u64> = HashChainLog::new();
        fresh.append(1);
        fresh.append(2);

        assert_eq!(resumed.root(), fresh.root());
        assert_eq!(resumed.next_seq(), fresh.next_seq());
    }

    #[test]
    fn test_entries_since_on_a_resumed_log_uses_absolute_seq() {
        let mut hot: HashChainLog<u64> = HashChainLog::resume_from(10, [0xABu8; 32]);
        hot.append(1);
        hot.append(2);
        hot.append(3);

        // Absolute seqs 10, 11, 12 -- NOT local indices 0, 1, 2.
        assert_eq!(
            hot.entries_since(11).len(),
            2,
            "seq 11 is the second entry, one must remain after it plus itself"
        );
        assert_eq!(hot.entries_since(10).len(), 3);
        // Anything before this log's own base_seq (already-archived
        // history it never held) clamps to everything it DOES have,
        // not an out-of-bounds panic.
        assert_eq!(hot.entries_since(0).len(), 3);
    }

    #[test]
    fn test_try_append_remote_mirrors_a_valid_sequence() {
        let mut source: HashChainLog<u64> = HashChainLog::new();
        source.append(1);
        source.append(2);
        source.append(3);

        let mut mirror: HashChainLog<u64> = HashChainLog::new();
        for entry in source.entries() {
            mirror
                .try_append_remote(entry.clone())
                .expect("valid entry should be accepted");
        }
        assert_eq!(mirror.root(), source.root());
        assert_eq!(mirror.len(), source.len());
    }

    #[test]
    fn test_try_append_remote_rejects_a_gap() {
        let mut source: HashChainLog<u64> = HashChainLog::new();
        source.append(1);
        source.append(2);

        let mut mirror: HashChainLog<u64> = HashChainLog::new();
        // Skips seq=0 entirely -- mirror never saw the first entry.
        let result = mirror.try_append_remote(source.entries()[1].clone());
        assert!(result.is_err());
        assert_eq!(mirror.len(), 0, "a rejected entry must not be appended");
    }

    #[test]
    fn test_try_append_remote_rejects_a_tampered_entry() {
        let mut source: HashChainLog<u64> = HashChainLog::new();
        source.append(1);

        let mut tampered = source.entries()[0].clone();
        tampered.payload = 999;

        let mut mirror: HashChainLog<u64> = HashChainLog::new();
        assert!(mirror.try_append_remote(tampered).is_err());
    }
}
