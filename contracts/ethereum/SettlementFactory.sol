// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./TraderEscrow.sol";
import "./BatchVerifier.sol";
import "./NodeRegistry.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SettlementFactory is EIP712 {
    using ECDSA for bytes32;

    BatchVerifier public verifier;
    NodeRegistry public registry;
    address public admin;
    mapping(address => address) public traderEscrows;

    // Matches TradeEntry's field order/types exactly -- see
    // commitTradeBatch's docs for why this exists at all.
    bytes32 private constant TRADE_ENTRY_TYPEHASH = keccak256(
        "TradeEntry(address trader,address counterparty,address token,uint256 amount,uint256 fee,uint256 deadline,bytes32 tradeHash,bytes32 assignedNode)"
    );

    // Measured live at ~148k gas/trade for commitTradeBatch (see
    // verify_batched_commit_perf). Mainnet's block gas limit is ~30M gas,
    // which puts the real ceiling around ~200 trades/call; 150 leaves
    // headroom for other transactions sharing the block and for L2s with
    // lower per-block gas limits. Without this cap, a relayer that built
    // too large a batch would get an opaque "exceeds block gas limit"
    // failure at inclusion time instead of a clear revert reason.
    uint256 public constant MAX_COMMIT_BATCH = 150;

    event EscrowCreated(address indexed trader, address escrowAddress, bytes32 offchainPubkey);
    event BatchSettled(bytes32 indexed batchRoot, uint256 tradeCount);
    event NodePenalized(bytes32 indexed nodePubkey, uint256 penalty);

    constructor(address _verifier, address _registry) EIP712("MEX-SettlementFactory", "1") {
        verifier = BatchVerifier(_verifier);
        registry = NodeRegistry(_registry);
        admin = msg.sender;
    }

    // Self-service only: a trader creates and binds their own escrow. This is
    // the only place the off-chain trading identity (an ed25519 pubkey used
    // to sign orders/matches in the off-chain matching engine) is bound to an
    // on-chain Ethereum account -- restricting this to msg.sender == trader
    // is what makes that binding trustworthy. Without it, anyone could
    // front-run a trader's first call with a bogus offchainPubkey and, since
    // only one escrow is ever allowed per trader address, permanently lock
    // them out of setting their real one.
    function createEscrow(address trader, bytes32 offchainPubkey) external returns (address) {
        require(msg.sender == trader, "Only self-service escrow creation");
        require(traderEscrows[trader] == address(0), "Escrow already exists");

        TraderEscrow escrow = new TraderEscrow();
        escrow.initialize(trader, address(this), offchainPubkey);

        traderEscrows[trader] = address(escrow);
        emit EscrowCreated(trader, address(escrow), offchainPubkey);
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
        bytes32 assignedNode;
    }

    struct FeeConfig {
        address feeRecipient;
        uint8 tier;
    }

    // Commits a trader to a pending trade: locks the funds and records the deadline and
    // the node responsible for settling it. This must happen *before* settlement so that
    // there is an on-chain window in which the deadline can pass unsettled -- otherwise
    // claimSlash could never observe a missed deadline, since recordSettlement and
    // settlement would always happen atomically in the same transaction.
    //
    // Only the trader themselves can commit their own escrow to a trade.
    function commitTrade(TradeEntry calldata trade) external {
        require(msg.sender == trade.trader, "Only trader can commit own trade");
        _commitTrade(trade);
    }

    // Batched form of commitTrade: instead of each trader submitting their
    // own transaction (msg.sender == trade.trader), each trade here is
    // authorized by an EIP-712 signature from that trade's own trader,
    // letting a relayer (typically the settlement node itself) submit many
    // traders' commits in one transaction. The on-chain EFFECT is
    // identical to calling commitTrade once per trade -- same lock(),
    // same recordSettlement(), same deadline -- this only changes how the
    // trader's authorization is proven, not what it authorizes or the
    // accountability commitTrade exists for. Replaying the same signature
    // twice is already rejected by recordSettlement's own
    // "Trade already recorded" check, so no separate nonce is needed here.
    function commitTradeBatch(
        TradeEntry[] calldata trades,
        bytes[] calldata signatures
    ) external {
        require(trades.length == signatures.length, "trades/signatures length mismatch");
        require(trades.length <= MAX_COMMIT_BATCH, "Batch exceeds MAX_COMMIT_BATCH");

        for (uint256 i = 0; i < trades.length; i++) {
            TradeEntry calldata trade = trades[i];

            bytes32 structHash = keccak256(abi.encode(
                TRADE_ENTRY_TYPEHASH,
                trade.trader,
                trade.counterparty,
                trade.token,
                trade.amount,
                trade.fee,
                trade.deadline,
                trade.tradeHash,
                trade.assignedNode
            ));
            address signer = _hashTypedDataV4(structHash).recover(signatures[i]);
            require(signer == trade.trader, "Invalid trader signature");

            _commitTrade(trade);
        }
    }

    function _commitTrade(TradeEntry calldata trade) private {
        require(block.timestamp <= trade.deadline, "Trade deadline passed");
        require(registry.isActiveNode(trade.assignedNode), "Assigned node not active");

        address escrowA = traderEscrows[trade.trader];
        address escrowB = traderEscrows[trade.counterparty];
        require(
            escrowA != address(0) && escrowB != address(0),
            "Escrows must exist"
        );

        uint256 totalLocked = trade.amount + trade.fee;
        TraderEscrow(escrowA).lock(trade.token, totalLocked);
        TraderEscrow(escrowA).recordSettlement(
            trade.tradeHash,
            trade.deadline,
            trade.assignedNode,
            trade.token,
            totalLocked,
            trade.counterparty
        );
    }

    // Fulfills trades that were previously committed via commitTrade. Funds must already
    // be locked and the settlement record already exist -- this function only moves the
    // already-locked funds and marks the trade settled, it does not create new obligations.
    //
    // Every TradeEntry field the caller supplies here is cross-checked against the
    // Settlement record commitTrade wrote (token, counterparty, amount+fee) before any
    // funds move. Without that, this function -- callable by anyone, since settlement is
    // meant to be submitted by whichever node was assigned, not restricted to a single
    // fixed address -- would let a caller settle a real trader's real committed trade
    // (identified only by its tradeHash, which is public) using an arbitrary amount,
    // token, or recipient of the caller's own choosing: getSettlement only proves SOME
    // trade with this hash was committed, not that the fields presented here match what
    // was actually agreed. The ZK proof alone does not protect against this either -- it
    // proves an off-chain arithmetic claim, not that this specific trades[] array is the
    // one it was generated for.
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

            require(
                registry.getNode(trade.assignedNode).operator == msg.sender,
                "Only the assigned node's operator can settle this trade"
            );

            address escrowA = traderEscrows[trade.trader];
            require(escrowA != address(0), "Escrow must exist");

            TraderEscrow.Settlement memory s = TraderEscrow(escrowA).getSettlement(trade.tradeHash);
            require(s.deadline > 0, "Trade not committed");
            require(!s.settled, "Trade already settled");
            require(!s.slashed, "Trade already slashed");
            require(block.timestamp <= s.deadline, "Trade deadline passed");
            require(trade.token == s.token, "Token does not match committed settlement");
            require(trade.counterparty == s.counterparty, "Counterparty does not match committed settlement");
            require(trade.amount + trade.fee == s.lockedAmount, "Amount/fee does not match committed settlement");

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

    // Slashes only the node that was actually assigned to a trade at settlement-recording
    // time (TradeEntry.assignedNode, stored via recordSettlement). The caller can only
    // claim against trades belonging to their own escrow, and only the node on record for
    // that trade can be slashed -- not an arbitrary caller-supplied node.
    function claimSlash(bytes32[] calldata tradeHashes) external {
        address escrow = traderEscrows[msg.sender];
        require(escrow != address(0), "No escrow for caller");

        for (uint256 i = 0; i < tradeHashes.length; i++) {
            bytes32 tradeHash = tradeHashes[i];

            TraderEscrow.Settlement memory s = TraderEscrow(escrow).getSettlement(tradeHash);

            require(s.deadline > 0, "Trade not recorded");
            require(block.timestamp > s.deadline, "Deadline not passed");
            require(!s.settled, "Trade was settled");
            require(!s.slashed, "Already slashed");
            require(s.assignedNode != bytes32(0), "No assigned node");

            TraderEscrow(escrow).markSettlementSlashed(tradeHash);

            uint256 stake = registry.getNode(s.assignedNode).stake;
            if (stake > 0) {
                // The caller (msg.sender) is who was actually wronged here --
                // their trade missed its deadline -- so the slashed stake
                // compensates them directly, instead of being stranded in
                // NodeRegistry with no way out.
                registry.slashNode(s.assignedNode, stake / 2, payable(msg.sender));
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
