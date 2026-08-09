#!/usr/bin/env node
// Stage P6-1b follow-up: compares dump_matrices.rs's (arkworks) and
// dump_circom_matrices.js's (circom) label-keyed R1CS constraint dumps.
// See EQUIVALENCE.md for the full writeup.
//
// Real wrinkles discovered while building this (not assumed up front,
// found by actually running it and inspecting mismatches):
//
//   1. Row order differs. arkworks emits constraints per-trade-slot
//      (mult, maker, taker, root, ...x8); circom's compiler groups by
//      constraint KIND in its final R1CS (all 8 multiplication
//      constraints first, then all 24 linear ones). Handled by
//      multiset matching, not positional comparison.
//
//   2. The SAME linear identity can be validly encoded as different
//      (A,B,C) triples. arkworks encodes `makerPost = makerPre + val`
//      as `(makerPre + val) * 1 = makerPost` (isolate one side in C,
//      multiply the other by the constant 1). circom's compiler
//      instead encodes it as `0 * 0 = (makerPre + val - makerPost)`
//      (fold the WHOLE identity into C, with A and B both empty/zero).
//      Both are correct R1CS encodings of the identical equation; a
//      row-shape comparison (even allowing an overall sign flip) can't
//      recognize them as the same constraint, because they're not
//      related by a scalar multiple applied to the SAME roles -- they
//      factor the identity differently.
//
// The only comparison that's actually correct here: expand each
// constraint into the polynomial it enforces to be zero -- A*B - C,
// as a normalized sum of monomials (degree <=2, since R1CS is
// bilinear: each A/B entry is linear, so A*B is at most a product of
// two linear forms) -- then compare the two circuits' polynomials up
// to an overall nonzero scalar (P(x)=0 and k*P(x)=0 are the same
// constraint for any nonzero k). This is factorization-independent:
// it doesn't matter HOW either compiler chose to split the identity
// across A/B/C, only what equation the constraint actually enforces.
const fs = require("fs");

const [, , arkworksPath, circomPath] = process.argv;
if (!arkworksPath || !circomPath) {
    console.error("usage: node diff_matrices.js <arkworks_matrices.json> <circom_matrices.json>");
    process.exit(1);
}

const arkworks = JSON.parse(fs.readFileSync(arkworksPath, "utf8"));
const circom = JSON.parse(fs.readFileSync(circomPath, "utf8"));

const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const mod = (n) => ((n % P) + P) % P;

// A monomial's canonical key: "one" (constant term), a single label
// (degree 1), or two labels joined and sorted (degree 2, from an A*B
// cross term where neither side is the constant).
function monomialKey(labels) {
    const real = labels.filter((l) => l !== "one");
    if (real.length === 0) return "one";
    real.sort();
    return real.join("*");
}

// Expands A*B - C into a Map<monomialKey, coefficient>, dropping
// zero-coefficient entries.
function expand(constraint) {
    const terms = new Map();
    const add = (key, coeff) => {
        const cur = terms.get(key) ?? 0n;
        const next = mod(cur + coeff);
        if (next === 0n) terms.delete(key);
        else terms.set(key, next);
    };

    const aEntries = Object.entries(constraint.a);
    const bEntries = Object.entries(constraint.b);
    for (const [aLabel, aCoeffStr] of aEntries) {
        for (const [bLabel, bCoeffStr] of bEntries) {
            const coeff = mod(BigInt(aCoeffStr) * BigInt(bCoeffStr));
            add(monomialKey([aLabel, bLabel]), coeff);
        }
    }
    for (const [cLabel, cCoeffStr] of Object.entries(constraint.c)) {
        add(monomialKey([cLabel]), mod(-BigInt(cCoeffStr)));
    }
    return terms;
}

// Canonicalizes a polynomial (Map<key, coeff>) up to an overall nonzero
// scalar: divides every coefficient by whichever coefficient belongs to
// the lexicographically-first key, so two polynomials that are scalar
// multiples of each other produce IDENTICAL canonical forms.
function modInverse(a) {
    // Fermat's little theorem: a^(P-2) mod P, P is prime (BN254 scalar
    // field order).
    let base = mod(a);
    let exp = P - 2n;
    let result = 1n;
    while (exp > 0n) {
        if (exp & 1n) result = mod(result * base);
        base = mod(base * base);
        exp >>= 1n;
    }
    return result;
}

function canonicalize(terms) {
    const keys = [...terms.keys()].sort();
    if (keys.length === 0) return "0";
    const pivotInv = modInverse(terms.get(keys[0]));
    return keys.map((k) => `${k}=${mod(terms.get(k) * pivotInv)}`).join(";");
}

const remaining = circom.map((c) => ({ raw: c, canon: canonicalize(expand(c)) }));
let matched = 0;
const unmatched = [];

for (const arkConstraint of arkworks) {
    const canon = canonicalize(expand(arkConstraint));
    const idx = remaining.findIndex((c) => c.canon === canon);
    if (idx !== -1) {
        matched++;
        remaining.splice(idx, 1);
    } else {
        unmatched.push({ constraint: arkConstraint, canon });
    }
}

console.log(`arkworks constraints: ${arkworks.length}`);
console.log(`circom constraints:   ${circom.length}`);
console.log(`matched (same polynomial identity, up to overall scalar): ${matched}`);
console.log(`unmatched (arkworks side): ${unmatched.length}`);
console.log(`unmatched (circom side): ${remaining.length}`);

if (unmatched.length > 0 || remaining.length > 0) {
    console.log("\n=== MISMATCH DETAIL ===");
    for (const { constraint, canon } of unmatched) {
        console.log("arkworks constraint with no circom match:", JSON.stringify(constraint), "canonical:", canon);
    }
    for (const { raw, canon } of remaining) {
        console.log("circom constraint with no arkworks match:", JSON.stringify(raw), "canonical:", canon);
    }
    process.exit(1);
}

console.log("\nAll 32 constraints represent the identical polynomial identity on both sides (up to how each compiler chose to factor it across A/B/C). No leftovers on either side.");
