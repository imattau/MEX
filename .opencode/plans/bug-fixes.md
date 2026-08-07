# MEX Bug Fix Plan

## Bug 1: Self-Trade Amount Burn (HIGH)
**File:** `crates/engine/src/book.rs` lines 46-52 (Buy) and 119-125 (Sell)

**Problem:** The self-trade check (`maker_order.trader == order.trader`) happens AFTER amounts are decremented. When the same trader matches against themselves, both `order.amount` and `maker_order.amount` are silently consumed but no `Match` is emitted. Amounts are burned.

**Fix:** Move the self-trade `continue` check BEFORE the amount decrements in both paths.

### Buy path (lines 46-52)
```rust
// BEFORE (buggy):
let match_amount = std::cmp::min(order.amount, maker_order.amount);
order.amount -= match_amount;
maker_order.amount -= match_amount;

if maker_order.trader == order.trader {
    continue;
}

// AFTER (fixed):
if maker_order.trader == order.trader {
    continue;
}

let match_amount = std::cmp::min(order.amount, maker_order.amount);
order.amount -= match_amount;
maker_order.amount -= match_amount;
```

### Sell path (lines 119-125)
Same reorder: move the `if maker_order.trader == order.trader { continue; }` block before the `match_amount` calculation and decrements.

### Test addition (`crates/engine/src/tests.rs`)
Add `test_self_trade_preserves_amounts`:
- Place a sell order from trader A
- Place a buy order from the same trader A at the same price
- Assert: matches is empty, both orders remain on the book with original amounts

---

## Bug 2: Unconstrained State Roots (MEDIUM)
**File:** `crates/prover/src/lib.rs` lines 83-84

**Problem:** `pre_root` and `post_root` are allocated as public input variables but have zero constraints (`let _ = pre_root; let _ = post_root;`). The ZK circuit accepts any arbitrary state root pair.

**Fix:** Replace the two `let _` lines with a linear commitment binding `post_root` to the post-balances and `pre_root`:

```rust
// BEFORE:
let _ = pre_root;
let _ = post_root;

// AFTER:
let mut lc_post = LinearCombination::zero();
lc_post = lc_post + (F::one(), pre_root) + (F::one(), maker_post) + (F::one(), taker_post);
cs.enforce_constraint(
    lc_post,
    LinearCombination::from(Variable::One),
    LinearCombination::from(post_root),
)?;
```

This enforces `post_root == pre_root + maker_post + taker_post`, preventing arbitrary root substitution.

### Test update (`crates/integration/tests/exploit_demo.rs`)
The `exploit_fake_state_transition` test currently documents the vulnerability. After the fix, the proof created with state roots `[0xAA; 32] -> [0xBB; 32]` will fail verification against a batch with `[0xFF; 32] -> [0x00; 32]` because the linear commitment won't hold. Update the test assertion to `assert!(!valid)`.

Note: The existing `test_zk_circuit_satisfied` test uses `pre_state_root: 0, post_state_root: 0` with `maker_post: 11, taker_post: 4`. After the fix: `0 + 11 + 4 = 15 != 0`. This test needs updating to use consistent values, e.g., `post_state_root: 15` (or `pre: 0, maker_post: 5, taker_post: 10, post: 15`).

Similarly `test_zk_circuit_unsatisfied_tampered_post_balance` and `test_bn254_prove_and_verify` need their state root values updated to satisfy the new constraint.

---

## Bug 3: Hardcoded Absolute Path (LOW)
**File:** `crates/simulator/src/main.rs` line 339

**Problem:** `/home/lostcause/workspace/MEX/latency_matrix.json` is an absolute path that fails on other machines.

**Fix:** Replace with a relative path or `--output` CLI arg:

```rust
// BEFORE:
if let Ok(mut file) = File::create("/home/lostcause/workspace/MEX/latency_matrix.json") {
    let _ = file.write_all(serialized.as_bytes());
    println!("Simulation report saved to /home/lostcause/workspace/MEX/latency_matrix.json");
}

// AFTER:
let output_path = args.iter()
    .position(|r| r == "--output")
    .and_then(|i| args.get(i + 1))
    .map(|s| s.as_str())
    .unwrap_or("latency_matrix.json");
if let Ok(mut file) = File::create(output_path) {
    let _ = file.write_all(serialized.as_bytes());
    println!("Simulation report saved to {}", output_path);
}
```

---

## Bug 4: Hardcoded API Key (MEDIUM)
**File:** `crates/api/src/server.rs` line 25

**Problem:** `"chronos-prod-key-2026"` is a string literal in source code.

**Fix:** Read from environment variable with dev fallback:

```rust
// BEFORE:
.map(|v| v == "chronos-prod-key-2026")

// AFTER:
let expected_key = std::env::var("MEX_API_KEY")
    .unwrap_or_else(|_| {
        tracing::warn!("MEX_API_KEY not set, using development default");
        "dev-default-key".to_string()
    });
// ... then in check_auth:
.map(|v| v == expected_key)
```

Since `check_auth` is an async fn (not a closure), the key needs to be accessible. The cleanest approach: use a `static` with `OnceLock<String>` initialized at app startup, or pass the key via Axum `Extension`/`State`.

Simplest approach: add a `lazy_static` or `OnceLock` at module level:

```rust
use std::sync::OnceLock;
static API_KEY: OnceLock<String> = OnceLock::new();

fn get_api_key() -> &'static str {
    API_KEY.get_or_init(|| {
        std::env::var("MEX_API_KEY").unwrap_or_else(|_| {
            eprintln!("WARNING: MEX_API_KEY not set, using development default");
            "dev-default-key".to_string()
        })
    })
}
```

Then in `check_auth`: `.map(|v| v == get_api_key())`

---

## Verification
After all fixes:
```bash
cargo test --workspace
cargo build --release
```
