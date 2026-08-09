require("@nomicfoundation/hardhat-toolbox");

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    // Bumped from 0.8.20 for @openzeppelin/contracts 5.x, which requires
    // ^0.8.24. evmVersion is explicitly "cancun" (not left to default,
    // and not the previous "paris") because OZ 5.6.1's Bytes.sol uses
    // MCOPY (EIP-5656), a Cancun opcode -- there's no way to add this
    // dependency while staying on Paris. Cancun has been live on Ethereum
    // mainnet and every major L2 since March 2024, so this is a
    // reasonable deployment target, but it IS a real change to what this
    // compiles to, not a no-op compiler bump.
    version: "0.8.24",
    settings: {
      evmVersion: "cancun",
      optimizer: {
        enabled: true,
        runs: 200,
      },
    },
  },
  paths: {
    sources: "./contracts/ethereum",
  },
  networks: {
    localhost: {
      // Overridable so docker-compose's deploy container can point this
      // at the chain container by its service name (chain:8545) instead
      // of 127.0.0.1, which inside that container would mean itself, not
      // the chain service -- see docker-compose.yml.
      url: process.env.HARDHAT_NETWORK_URL || "http://127.0.0.1:8545",
    },
    // Real deployment targets, not just gas-unit benchmarking -- deploying
    // here is a real, irreversible mainnet action and costs real ETH, so
    // none of this is wired into any automated script. Confirmed live
    // (2026-08-08) that this repo's contracts deploy and run correctly
    // under each of these chains' actual EVM state via `hardhat node
    // --fork <rpc>` against a local, funds-free fork -- see
    // verify_batched_commit_perf's results for Arbitrum specifically.
    // Gas *unit* costs (gasUsed) are identical to L1 on all three, since
    // they're EVM-equivalent; the saving comes entirely from gas *price*
    // being far lower. Arbitrum folds L1 data-availability cost into
    // gasUsed itself; Base/Optimism (OP-stack) charge it as a *separate*
    // L1 fee on top of gasUsed * gasPrice, so their L2-only gas price
    // alone understates real total cost -- budget accordingly rather than
    // reading gasPrice ratios as the full savings multiplier.
    arbitrum: {
      url: process.env.ARBITRUM_RPC_URL || "https://arb1.arbitrum.io/rpc",
      chainId: 42161,
      accounts: process.env.DEPLOYER_PRIVATE_KEY ? [process.env.DEPLOYER_PRIVATE_KEY] : [],
    },
    base: {
      url: process.env.BASE_RPC_URL || "https://mainnet.base.org",
      chainId: 8453,
      accounts: process.env.DEPLOYER_PRIVATE_KEY ? [process.env.DEPLOYER_PRIVATE_KEY] : [],
    },
    optimism: {
      url: process.env.OPTIMISM_RPC_URL || "https://mainnet.optimism.io",
      chainId: 10,
      accounts: process.env.DEPLOYER_PRIVATE_KEY ? [process.env.DEPLOYER_PRIVATE_KEY] : [],
    },
  },
};
