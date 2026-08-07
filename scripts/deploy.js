// Deploys BatchVerifier, NodeRegistry, and SettlementFactory, and wires them
// together: NodeRegistry.slashingAuthority must point at SettlementFactory,
// or slashNode()/updateReputation() revert for every call SettlementFactory
// makes (claimSlash and fee-compliance slashing would always fail).
//
// Usage:
//   npx hardhat run scripts/deploy.js --network <network>
//
// Env vars:
//   BATCH_VERIFIER_ADDRESS  Reuse an already-deployed BatchVerifier instead of
//                           deploying a new one.
//   VERIFYING_KEY_PATH      Path to a JSON file with the Groth16 verifying key
//                           as { alpha, beta, gamma, delta, ic }, each entry a
//                           uint256 or uint256[2]/uint256[2][2] matching
//                           BatchVerifier's constructor. Required unless
//                           BATCH_VERIFIER_ADDRESS is set or you accept the
//                           placeholder key described below.
const hre = require("hardhat");
const fs = require("fs");

// Only used when neither BATCH_VERIFIER_ADDRESS nor VERIFYING_KEY_PATH is
// given, so this script can still deploy end-to-end on a local/dev network.
// It is NOT a real verifying key and will not verify real Groth16 proofs --
// never use it past local wiring tests.
const PLACEHOLDER_VERIFYING_KEY = {
  alpha: [1, 2],
  beta: [
    [1, 2],
    [3, 4],
  ],
  gamma: [
    [1, 2],
    [3, 4],
  ],
  delta: [
    [1, 2],
    [3, 4],
  ],
  ic: [
    [1, 2],
    [1, 2],
  ],
};

function loadVerifyingKey() {
  const vkPath = process.env.VERIFYING_KEY_PATH;
  if (!vkPath) {
    console.warn(
      "WARNING: VERIFYING_KEY_PATH not set -- deploying BatchVerifier with a " +
        "placeholder verifying key. This will NOT verify real Groth16 proofs. " +
        "Set VERIFYING_KEY_PATH to a JSON file with { alpha, beta, gamma, delta, ic } " +
        "before deploying anywhere but a local/dev network."
    );
    return PLACEHOLDER_VERIFYING_KEY;
  }
  return JSON.parse(fs.readFileSync(vkPath, "utf8"));
}

async function deployBatchVerifier() {
  const existing = process.env.BATCH_VERIFIER_ADDRESS;
  if (existing) {
    const batchVerifier = await hre.ethers.getContractAt("BatchVerifier", existing);
    console.log("Using existing BatchVerifier at", existing);
    return batchVerifier;
  }

  const vk = loadVerifyingKey();
  const BatchVerifier = await hre.ethers.getContractFactory("BatchVerifier");
  const batchVerifier = await BatchVerifier.deploy(vk.alpha, vk.beta, vk.gamma, vk.delta, vk.ic);
  await batchVerifier.waitForDeployment();
  console.log("BatchVerifier deployed to:", await batchVerifier.getAddress());
  return batchVerifier;
}

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  console.log("Deploying with account:", deployer.address);

  const batchVerifier = await deployBatchVerifier();

  const NodeRegistry = await hre.ethers.getContractFactory("NodeRegistry");
  const registry = await NodeRegistry.deploy();
  await registry.waitForDeployment();
  console.log("NodeRegistry deployed to:", await registry.getAddress());

  const SettlementFactory = await hre.ethers.getContractFactory("SettlementFactory");
  const settlementFactory = await SettlementFactory.deploy(
    await batchVerifier.getAddress(),
    await registry.getAddress()
  );
  await settlementFactory.waitForDeployment();
  console.log("SettlementFactory deployed to:", await settlementFactory.getAddress());

  const tx = await registry.setSlashingAuthority(await settlementFactory.getAddress());
  await tx.wait();
  console.log("NodeRegistry.slashingAuthority set to SettlementFactory");

  const summary = {
    batchVerifier: await batchVerifier.getAddress(),
    nodeRegistry: await registry.getAddress(),
    settlementFactory: await settlementFactory.getAddress(),
  };
  console.log("\nDeployment summary:");
  console.log(JSON.stringify(summary, null, 2));

  return summary;
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
