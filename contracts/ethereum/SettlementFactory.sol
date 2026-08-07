// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./TraderEscrow.sol";
import "./BatchVerifier.sol";
import "./NodeRegistry.sol";

contract SettlementFactory {
    BatchVerifier public verifier;
    NodeRegistry public registry;
    address public admin;
    mapping(address => address) public traderEscrows;

    event EscrowCreated(address indexed trader, address escrowAddress);
    event BatchSettled(bytes32 indexed batchRoot, uint256 tradeCount);
    event NodePenalized(bytes32 indexed nodePubkey, uint256 penalty);

    constructor(address _verifier, address _registry) {
        verifier = BatchVerifier(_verifier);
        registry = NodeRegistry(_registry);
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
        uint256[] calldata input
    ) external {
        require(input.length > 0, "Inputs cannot be empty");

        require(
            verifier.verifyProof(a, b, c, input),
            "Invalid ZK proof"
        );

        address escrowA = traderEscrows[traderA];
        address escrowB = traderEscrows[traderB];
        require(
            escrowA != address(0) && escrowB != address(0),
            "Escrows must exist"
        );

        TraderEscrow(escrowA).lock(tokenA, amountA);
        TraderEscrow(escrowB).lock(tokenB, amountB);

        TraderEscrow(escrowA).settle(tokenA, traderB, amountA);
        TraderEscrow(escrowB).settle(tokenB, traderA, amountB);

        emit BatchSettled(bytes32(input[0]), 1);
    }

    struct TradeEntry {
        address trader;
        address counterparty;
        address token;
        uint256 amount;
        uint256 fee;
        uint256 deadline;
        bytes32 tradeHash;
    }

    struct FeeConfig {
        address feeRecipient;
        uint8 tier;
    }

    function settleBatchWithFees(
        TradeEntry[] calldata trades,
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[] calldata input,
        FeeConfig calldata feeConfig
    ) external {
        require(trades.length > 0, "No trades to settle");
        require(input.length > 0, "Inputs cannot be empty");

        require(
            verifier.verifyProof(a, b, c, input),
            "Invalid ZK proof"
        );

        for (uint256 i = 0; i < trades.length; i++) {
            TradeEntry calldata trade = trades[i];

            require(block.timestamp <= trade.deadline, "Trade deadline passed");

            address escrowA = traderEscrows[trade.trader];
            address escrowB = traderEscrows[trade.counterparty];
            require(
                escrowA != address(0) && escrowB != address(0),
                "Escrows must exist"
            );

            TraderEscrow(escrowA).lock(trade.token, trade.amount + trade.fee);

            TraderEscrow(escrowA).recordSettlement(trade.tradeHash, trade.deadline);

            TraderEscrow(escrowA).settleWithFee(
                trade.token,
                trade.counterparty,
                trade.amount,
                trade.fee,
                feeConfig.feeRecipient
            );

            TraderEscrow(escrowA).markSettlementSettled(trade.tradeHash);
        }

        emit BatchSettled(bytes32(input[0]), trades.length);
    }

    function claimSlash(
        bytes32 batchRoot,
        bytes32[] calldata tradeHashes,
        bytes32[] calldata nodePubkeys
    ) external {
        for (uint256 i = 0; i < tradeHashes.length; i++) {
            bytes32 tradeHash = tradeHashes[i];

            bool nodeFailed = false;
            for (uint256 j = 0; j < nodePubkeys.length; j++) {
                bytes32 nodePubkey = nodePubkeys[j];

                for (uint256 k = 0; k < nodePubkeys.length; k++) {
                    bytes32 checkHash = keccak256(abi.encodePacked(batchRoot, tradeHash, nodePubkeys[k]));
                    address escrow = traderEscrows[msg.sender];
                    if (escrow != address(0)) {
                        try TraderEscrow(escrow).settlements(tradeHash) returns (
                            TraderEscrow.Settlement memory s
                        ) {
                            if (s.deadline > 0 && block.timestamp > s.deadline && !s.settled) {
                                nodeFailed = true;
                                break;
                            }
                        } catch {
                            continue;
                        }
                    }
                }
                if (nodeFailed) break;
            }

            if (nodeFailed) {
                for (uint256 j = 0; j < nodePubkeys.length; j++) {
                    uint256 stake = registry.nodes(nodePubkeys[j]).stake;
                    if (stake > 0) {
                        registry.slashNode(nodePubkeys[j], stake / 2);
                    }
                }
            }
        }
    }

    function getEscrow(address trader) external view returns (address) {
        return traderEscrows[trader];
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    function updateVerifier(address _verifier) external onlyAdmin {
        verifier = BatchVerifier(_verifier);
    }

    function updateRegistry(address _registry) external onlyAdmin {
        registry = NodeRegistry(_registry);
    }
}
