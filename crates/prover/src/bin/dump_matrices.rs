// Stage P6-1b follow-up: dumps DEXBatchCircuit's actual R1CS A/B/C
// matrices, with every column labeled by what it semantically IS
// (trade[i].maker_pre, pre_root, etc.) rather than left as a raw
// arkworks-internal index -- raw indices aren't comparable to circom's
// own numbering at all (circom allocates all of one signal array
// contiguously, e.g. every makerPre[] entry together; arkworks
// allocates per-trade-slot, interleaving maker_pre/taker_pre/amount/
// .../next_root for slot 0, then slot 1, etc. -- same variables,
// completely different raw column order). Labeling both sides by
// semantic name before comparing is what makes a real diff meaningful.
//
// Usage: cargo run -p prover --bin dump_matrices -- <output.json>
// Paired with circom/dump_circom_matrices.js, which does the same for
// the compiled circom circuit, and circom/diff_matrices.js, which
// compares the two label-keyed dumps. See circom/EQUIVALENCE.md.

use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
use prover::{DEXBatchCircuit, MAX_BATCH_TRADES};

// The exact allocation order DEXBatchCircuit::generate_constraints
// uses -- see that function's own source. Column 0 is always the
// implicit constant "one" in arkworks' convention (never part of
// `instance`/`witness` here); instance variables occupy columns
// 1..=instance.len(); witness variables occupy every column after
// that, in this order.
fn column_labels(n: usize) -> (Vec<String>, Vec<String>) {
    let instance = vec!["pre_root".to_string(), "post_root".to_string()];
    let mut witness = Vec::new();
    for i in 0..n {
        witness.push(format!("trade[{i}].maker_pre"));
        witness.push(format!("trade[{i}].taker_pre"));
        witness.push(format!("trade[{i}].amount"));
        witness.push(format!("trade[{i}].price"));
        witness.push(format!("trade[{i}].val"));
        witness.push(format!("trade[{i}].maker_post"));
        witness.push(format!("trade[{i}].taker_post"));
        // Last slot's "next root" IS post_root_var (already labeled
        // above as an instance variable) -- generate_constraints
        // never allocates a fresh witness variable for it, so no
        // corresponding witness label here either.
        if i < n - 1 {
            witness.push(format!("trade[{i}].next_root"));
        }
    }
    (instance, witness)
}

fn label_for(col: usize, instance: &[String], witness: &[String]) -> String {
    if col == 0 {
        "one".to_string()
    } else if col <= instance.len() {
        instance[col - 1].clone()
    } else {
        witness[col - 1 - instance.len()].clone()
    }
}

fn row_to_json(row: &[(Fr, usize)], instance: &[String], witness: &[String]) -> serde_json::Value {
    let mut entries: Vec<(String, String)> = row
        .iter()
        .map(|(coeff, col)| {
            (
                label_for(*col, instance, witness),
                coeff.into_bigint().to_string(),
            )
        })
        .collect();
    // Sorted so the JSON is stable/diffable regardless of arkworks'
    // internal sparse-row ordering.
    entries.sort();
    serde_json::Value::Object(
        entries
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect(),
    )
}

fn main() {
    let output_path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: dump_matrices <output.json>");
        std::process::exit(1);
    });

    // Structural dump only -- matrices depend on the circuit's SHAPE,
    // not the witness values, so any concrete, non-panicking assignment
    // works. Mirrors bn254::setup_circuit's own dummy witness.
    let dummy_trades = vec![(10u64, 10u64, 1u64, 1u64); MAX_BATCH_TRADES];
    let mut root = Fr::from(0u64);
    let mut maker_pre = Vec::new();
    let mut taker_pre = Vec::new();
    let mut amount = Vec::new();
    let mut price = Vec::new();
    let mut maker_post = Vec::new();
    let mut taker_post = Vec::new();
    let mut intermediate_roots = Vec::new();
    for (i, &(mb, tb, a, p)) in dummy_trades.iter().enumerate() {
        let val = Fr::from(a) * Fr::from(p);
        maker_pre.push(Some(Fr::from(mb)));
        taker_pre.push(Some(Fr::from(tb)));
        amount.push(Some(Fr::from(a)));
        price.push(Some(Fr::from(p)));
        maker_post.push(Some(Fr::from(mb) + val));
        taker_post.push(Some(Fr::from(tb) - val));
        root += val;
        if i < MAX_BATCH_TRADES - 1 {
            intermediate_roots.push(Some(root));
        }
    }
    let circuit = DEXBatchCircuit::<Fr> {
        maker_balance_pre: maker_pre,
        taker_balance_pre: taker_pre,
        amount,
        price,
        maker_balance_post: maker_post,
        taker_balance_post: taker_post,
        intermediate_roots,
        pre_state_root: Some(Fr::from(0u64)),
        post_state_root: Some(root),
    };

    let cs = ConstraintSystem::<Fr>::new();
    let cs_ref = ConstraintSystemRef::new(cs);
    circuit
        .generate_constraints(cs_ref.clone())
        .expect("synthesis failed");
    cs_ref.finalize();
    let matrices = cs_ref
        .to_matrices()
        .expect("to_matrices returned None -- was this built with construct_matrices: false?");

    let (instance, witness) = column_labels(MAX_BATCH_TRADES);
    assert_eq!(
        instance.len() + 1,
        matrices.num_instance_variables,
        "column_labels' instance schedule must match the circuit's real instance-variable count"
    );
    assert_eq!(
        witness.len(),
        matrices.num_witness_variables,
        "column_labels' witness schedule must match the circuit's real witness-variable count"
    );

    let constraints: Vec<serde_json::Value> = (0..matrices.num_constraints)
        .map(|i| {
            serde_json::json!({
                "a": row_to_json(&matrices.a[i], &instance, &witness),
                "b": row_to_json(&matrices.b[i], &instance, &witness),
                "c": row_to_json(&matrices.c[i], &instance, &witness),
            })
        })
        .collect();

    std::fs::write(
        &output_path,
        serde_json::to_string_pretty(&constraints).unwrap(),
    )
    .unwrap_or_else(|e| {
        eprintln!("failed to write {output_path}: {e}");
        std::process::exit(1);
    });
    println!(
        "wrote {} labeled constraints to {output_path}",
        constraints.len()
    );
}
