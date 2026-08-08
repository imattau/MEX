// Registers a settlement node in an already-deployed NodeRegistry -- a
// companion to deploy.js for standing up a real node operator, whether
// for a live run of crates/api or a manual devnet test.
//
// Usage:
//   npx hardhat run scripts/register_node.js --network <network>
//
// Env vars (all required):
//   NODE_REGISTRY_ADDRESS   The deployed NodeRegistry's address.
//   NODE_OPERATOR_KEY       Private key of the account registering as this
//                           node's operator -- this is the same key
//                           crates/api's MEX_NODE_PRIVATE_KEY must use, and
//                           the address that ends up as msg.sender for every
//                           settleBatchWithFees call this node submits.
//   NODE_PUBKEY             32-byte hex pubkey identifying this node
//                           on-chain -- must match crates/api's
//                           MEX_SETTLEMENT_NODE_PUBKEY exactly.
//   NODE_STAKE_ETH          Stake to register with, in whole ETH. Must meet
//                           or exceed whatever MIN_STAKE this NodeRegistry
//                           was deployed with (see deploy.js's
//                           NODE_MIN_STAKE_ETH).
//   NODE_GEO_REGION         Free-text region label. Defaults to "unspecified".
const hre = require("hardhat");

function requireEnv(name) {
  const value = process.env[name];
  if (!value) {
    console.error(`required environment variable ${name} not set`);
    process.exit(1);
  }
  return value;
}

async function main() {
  const registryAddress = requireEnv("NODE_REGISTRY_ADDRESS");
  const operatorKey = requireEnv("NODE_OPERATOR_KEY");
  const nodePubkeyHex = requireEnv("NODE_PUBKEY");
  const stakeEth = requireEnv("NODE_STAKE_ETH");
  const geoRegion = process.env.NODE_GEO_REGION || "unspecified";

  const nodePubkey = nodePubkeyHex.startsWith("0x") ? nodePubkeyHex : `0x${nodePubkeyHex}`;
  if (nodePubkey.length !== 66) {
    console.error(`NODE_PUBKEY must be exactly 32 bytes (64 hex chars), got ${nodePubkey.length - 2}`);
    process.exit(1);
  }

  const operator = new hre.ethers.Wallet(operatorKey, hre.ethers.provider);
  const registry = await hre.ethers.getContractAt("NodeRegistry", registryAddress, operator);

  const alreadyActive = await registry.isActiveNode(nodePubkey);
  if (alreadyActive) {
    console.log(`Node ${nodePubkey} is already active, nothing to do.`);
    return;
  }

  const tx = await registry.registerNode(nodePubkey, geoRegion, {
    value: hre.ethers.parseEther(stakeEth),
  });
  await tx.wait();

  console.log(`Node registered:`);
  console.log(JSON.stringify({
    nodePubkey,
    operator: operator.address,
    stakeEth,
    geoRegion,
    registryAddress,
  }, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
