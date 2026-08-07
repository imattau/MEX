// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./TraderEscrow.sol";
import "./BatchVerifier.sol";

contract SettlementFactory {
    address public verifier;
    address public admin;
    mapping(address => address) public traderEscrows;

    event EscrowCreated(address indexed trader, address escrowAddress);
    event BatchSettled(bytes32 indexed batchRoot);

    constructor(address _verifier) {
        verifier = _verifier;
        admin = msg.sender;
    }

    function createEscrow(address trader) external returns (address) {
        require(traderEscrows[trader] == address(0), "Escrow already exists");
        
        TraderEscrow escrow = new TraderEscrow();
        escrow.initialize(trader, address(this));
        
        traderEscrows[trader] = address(escrow);
        emit EscrowCreated(trader, address(escrow));
        return address(escrow);
    }

    function settleBatch(
        address traderA,
        address traderB,
        address tokenA,
        address tokenB,
        uint256 amountA,
        uint256 amountB,
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[4] calldata input
    ) external {
        // 1. Verify ZK Proof via verifier
        require(BatchVerifier(verifier).verifyProof(a, b, c, input), "Invalid ZK proof");

        // 2. Perform atomic settlement swap
        address escrowA = traderEscrows[traderA];
        address escrowB = traderEscrows[traderB];
        require(escrowA != address(0) && escrowB != address(0), "Escrows must exist");

        // Lock funds
        TraderEscrow(escrowA).lock(tokenA, amountA);
        TraderEscrow(escrowB).lock(tokenB, amountB);

        // Swap settle
        TraderEscrow(escrowA).settle(tokenA, traderB, amountA);
        TraderEscrow(escrowB).settle(tokenB, traderA, amountB);

        emit BatchSettled(bytes32(input[0]));
    }
}
