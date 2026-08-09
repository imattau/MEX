// Orchestrates a from-scratch local devnet for docker-compose: waits for
// the Hardhat node to accept RPC calls, deploys the contracts (deploy.js),
// registers this compose setup's one fixed devnet node (register_node.js),
// and writes an env file the api container sources before starting.
//
// Every key/address here is one of Hardhat's well-known, publicly
// documented default devnet accounts -- fine to hardcode because they're
// already public and only ever funded on this ephemeral local chain.
// NEVER reuse these for anything real.
const { execFileSync } = require("child_process");
const fs = require("fs");

const RPC_URL = "http://chain:8545";
const DEPLOYMENT_PATH = "/shared/deployment.json";
const ENV_PATH = "/shared/mex.env";

// Hardhat default account #1 -- distinct from account #0, which
// deploy.js implicitly uses as the deployer via the localhost network's
// own unlocked accounts (see hardhat.config.js: no explicit `accounts`
// list for localhost, so ethers.getSigners() returns the node's funded
// accounts directly).
const NODE_OPERATOR_KEY =
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const NODE_PUBKEY =
  "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

async function waitForChain() {
  for (let i = 0; i < 60; i++) {
    try {
      const res = await fetch(RPC_URL, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_blockNumber", params: [] }),
      });
      if (res.ok) {
        console.log("chain is up");
        return;
      }
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error("timed out waiting for the chain service to accept RPC calls");
}

function run(script, env) {
  execFileSync("npx", ["hardhat", "run", script, "--network", "localhost"], {
    stdio: "inherit",
    // HARDHAT_NETWORK_URL: see hardhat.config.js -- 127.0.0.1 inside
    // this container would mean itself, not the chain service.
    env: { ...process.env, HARDHAT_NETWORK_URL: RPC_URL, ...env },
  });
}

async function main() {
  await waitForChain();

  run("scripts/deploy.js", {
    NODE_MIN_STAKE_ETH: "10",
    DEPLOYMENT_OUTPUT_PATH: DEPLOYMENT_PATH,
  });
  const deployment = JSON.parse(fs.readFileSync(DEPLOYMENT_PATH, "utf8"));

  run("scripts/register_node.js", {
    NODE_REGISTRY_ADDRESS: deployment.nodeRegistry,
    NODE_OPERATOR_KEY,
    NODE_PUBKEY,
    NODE_STAKE_ETH: "10",
    NODE_GEO_REGION: "local-devnet",
  });

  const envFile = [
    "MEX_API_KEY=devnet-local-api-key",
    `MEX_RPC_URL=${RPC_URL}`,
    `MEX_NODE_PRIVATE_KEY=${NODE_OPERATOR_KEY}`,
    `MEX_FACTORY_ADDRESS=${deployment.settlementFactory}`,
    `MEX_REGISTRY_ADDRESS=${deployment.nodeRegistry}`,
    `MEX_SETTLEMENT_NODE_PUBKEY=${NODE_PUBKEY}`,
    "",
  ].join("\n");
  fs.writeFileSync(ENV_PATH, envFile);
  console.log(`wrote ${ENV_PATH}:\n${envFile}`);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
