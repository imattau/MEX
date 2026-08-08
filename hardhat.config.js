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
      url: "http://127.0.0.1:8545",
    },
  },
};
