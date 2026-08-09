#!/usr/bin/env node
// Stage P6-1b follow-up: converts a compiled circom circuit's R1CS
// (via `snarkjs r1cs export json`) into the same label-keyed shape
// dump_matrices.rs produces for the arkworks side, using the .sym file
// to map circom's raw wire indices back to signal names -- see
// diff_matrices.js for the actual comparison, and EQUIVALENCE.md for
// why label-keyed comparison (not raw index comparison) is the only
// meaningful kind here: circom and arkworks allocate the same
// variables in completely different raw orders (circom groups by
// signal array, e.g. all of makerPre[] together; arkworks groups by
// trade slot).
//
// Usage: node dump_circom_matrices.js <circuit.r1cs.json> <circuit.sym> <output.json>
const fs = require("fs");

const [, , r1csJsonPath, symPath, outPath] = process.argv;
if (!r1csJsonPath || !symPath || !outPath) {
    console.error("usage: node dump_circom_matrices.js <circuit.r1cs.json> <circuit.sym> <output.json>");
    process.exit(1);
}

const r1cs = JSON.parse(fs.readFileSync(r1csJsonPath, "utf8"));

// wire 0 is always the implicit constant in both circom and arkworks --
// labeled "one" to match dump_matrices.rs exactly.
const wireLabel = { 0: "one" };
for (const line of fs.readFileSync(symPath, "utf8").trim().split("\n")) {
    const [wireIdx, , , fullName] = line.split(",");
    // fullName looks like "main.makerPre[3]" -- strip the "main."
    // prefix and translate circom's camelCase field names to the
    // snake_case labels dump_matrices.rs uses, so both sides produce
    // IDENTICAL label strings for the same semantic variable.
    let label = fullName.replace(/^main\./, "");
    label = label
        .replace(/^preRoot$/, "pre_root")
        .replace(/^postRoot$/, "post_root")
        .replace(/^makerPre\[(\d+)\]$/, "trade[$1].maker_pre")
        .replace(/^takerPre\[(\d+)\]$/, "trade[$1].taker_pre")
        .replace(/^amount\[(\d+)\]$/, "trade[$1].amount")
        .replace(/^price\[(\d+)\]$/, "trade[$1].price")
        .replace(/^makerPost\[(\d+)\]$/, "trade[$1].maker_post")
        .replace(/^takerPost\[(\d+)\]$/, "trade[$1].taker_post")
        .replace(/^val\[(\d+)\]$/, "trade[$1].val");
    // intermediateRoots[i] plays the SAME semantic role as arkworks'
    // "trade[i].next_root" (the root threaded out of slot i) -- see
    // dex_batch.circom's own docs on this correspondence.
    const introot = label.match(/^intermediateRoots\[(\d+)\]$/);
    if (introot) {
        label = `trade[${introot[1]}].next_root`;
    }
    wireLabel[wireIdx] = label;
}

function rowToLabeled(row) {
    // row is {wireIndexString: coeffDecimalString}
    const out = {};
    for (const [wireIdx, coeff] of Object.entries(row)) {
        const label = wireLabel[wireIdx];
        if (label === undefined) {
            throw new Error(`no label for wire ${wireIdx} -- .sym file doesn't cover it (runningRoot, maybe? check dex_batch.circom's optimizer-eliminated signals)`);
        }
        out[label] = coeff;
    }
    return out;
}

const constraints = r1cs.constraints.map(([a, b, c]) => ({
    a: rowToLabeled(a),
    b: rowToLabeled(b),
    c: rowToLabeled(c),
}));

fs.writeFileSync(outPath, JSON.stringify(constraints, null, 2));
console.log(`wrote ${constraints.length} labeled constraints to ${outPath}`);
