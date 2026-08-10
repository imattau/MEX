//! MEX settlement contract for FRG (https://github.com/imattau/FRG),
//! playing the role `SettlementFactory.sol`/`BatchVerifier.sol` play on
//! Ethereum: verifying a Groth16 batch proof and recording which trades it
//! covers as settled.
//!
//! ## Scope -- what this contract does NOT do
//!
//! Unlike `SettlementFactory.sol`, this contract does not implement
//! trader escrow deposits, fee-tier transfers, or missed-deadline
//! slashing. It only does the part `chain::ChainAdapter::is_trade_settled`
//! and `::submit_settlement_batch` actually need: verify the batch proof
//! and mark each covered trade's hash as settled, queryable via FRG's
//! generic `GetContractState`/`/contracts/state` API with no extra
//! contract-side read entrypoint required. Escrow/fees/slashing would need
//! the `frg::transfer` host function and a much larger design; deliberately
//! left for later rather than half-built here.
//!
//! ## Exported functions (selected by the calldata's first 4 bytes --
//! see `core/contract/contract.go`)
//!
//! - `init` -- no-op. The verifying key is compiled in (`vk.rs`), not
//!   passed at deploy time: FRG's `Deploy` never populates `init`'s
//!   calldata, so there's no constructor-argument channel to use instead
//!   (unlike `BatchVerifier.sol`, which takes the VK as constructor args).
//! - `sett` -- verifies a batch proof and records its trades as settled.
//!   See `groth16.rs`'s module docs for the calldata format. Traps
//!   (WASM `unreachable`) on any malformed input or failed verification,
//!   which FRG surfaces as a failed transaction (state changes discarded).
//!
//! ## Untested against a live FRG node
//!
//! This crate's test suite (`groth16.rs`) verifies the pure Groth16 math
//! against real proofs from `crates/prover`, and this file compiles to a
//! real `wasm32-unknown-unknown` module importing only from `"frg"`/`"env"`
//! (FRG's `validateModule` requirement). Neither proves this contract
//! actually deploys and runs correctly on a live FRG node -- that needs an
//! actual devnet, not available in the environment this was written in.

#![cfg_attr(not(test), no_std)]
extern crate alloc;

mod encoding;
mod groth16;
mod vk;

#[cfg(all(target_arch = "wasm32", not(test)))]
mod wasm_entry {
    use super::groth16::{self, MAX_CALLDATA_LEN};
    use core::arch::wasm32::unreachable;

    #[link(wasm_import_module = "frg")]
    extern "C" {
        fn calldata_len() -> i32;
        fn calldata_copy(dst_ptr: i32, offset: i32, max_len: i32) -> i32;
        fn state_set(key_ptr: i32, key_len: i32, val_ptr: i32, val_len: i32) -> i32;
        fn bn254_pairing_check(input_ptr: i32, input_len: i32) -> i32;
    }

    #[no_mangle]
    pub extern "C" fn init() {
        // Nothing to do -- see module docs.
    }

    #[no_mangle]
    pub extern "C" fn sett() {
        let len = unsafe { calldata_len() };
        if len <= 0 || len as usize > MAX_CALLDATA_LEN {
            unreachable()
        }
        let len = len as usize;

        let mut buf = [0u8; MAX_CALLDATA_LEN];
        let copied = unsafe { calldata_copy(buf.as_mut_ptr() as i32, 0, len as i32) };
        if copied != len as i32 {
            unreachable()
        }

        let batch = match groth16::parse_calldata(&buf[..len]) {
            Some(b) => b,
            None => unreachable(),
        };

        let pairing_input = match groth16::build_pairing_input(&batch) {
            Some(b) => b,
            None => unreachable(),
        };

        let valid = unsafe {
            bn254_pairing_check(pairing_input.as_ptr() as i32, pairing_input.len() as i32)
        };
        if valid != 1 {
            unreachable()
        }

        for hash in &batch.trade_hashes {
            let value = [1u8];
            let rc = unsafe {
                state_set(
                    hash.as_ptr() as i32,
                    32,
                    value.as_ptr() as i32,
                    value.len() as i32,
                )
            };
            if rc != 0 {
                unreachable()
            }
        }
    }
}

// A no_std lib crate needs a panic handler when built as the final wasm
// artifact (cdylib); `cargo test` links against std instead, which
// supplies its own, so this must not be defined there too.
#[cfg(all(not(test), target_arch = "wasm32"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

// FRG's WASM contracts get no host-provided allocator, so this needs its
// own -- deliberately a bump allocator with no dealloc (matches FRG's own
// benchmarks/bn254_wasm precedent): a contract call is short-lived and
// fully torn down after each invocation, so leaking within one call's
// arena is fine and far simpler than real bookkeeping.
#[cfg(all(not(test), target_arch = "wasm32"))]
mod alloc_impl {
    use core::alloc::{GlobalAlloc, Layout};
    use core::sync::atomic::{AtomicUsize, Ordering};

    const HEAP_SIZE: usize = 2 * 1024 * 1024;
    static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];
    static NEXT: AtomicUsize = AtomicUsize::new(0);

    struct BumpAlloc;

    unsafe impl GlobalAlloc for BumpAlloc {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let align = layout.align();
            let size = layout.size();
            let mut current = NEXT.load(Ordering::Relaxed);
            loop {
                let aligned = (current + align - 1) & !(align - 1);
                let next = match aligned.checked_add(size) {
                    Some(next) if next <= HEAP_SIZE => next,
                    _ => return core::ptr::null_mut(),
                };
                match NEXT.compare_exchange(current, next, Ordering::SeqCst, Ordering::Relaxed) {
                    Ok(_) => return (core::ptr::addr_of_mut!(HEAP) as *mut u8).add(aligned),
                    Err(observed) => current = observed,
                }
            }
        }

        unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
    }

    #[global_allocator]
    static ALLOC: BumpAlloc = BumpAlloc;
}
