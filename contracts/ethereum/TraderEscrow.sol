// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract TraderEscrow {
    address public factory;
    address public owner;
    // The off-chain ed25519 pubkey used to sign orders/matches in the
    // off-chain matching engine, bound once at creation by
    // SettlementFactory.createEscrow. This is what lets on-chain deposits be
    // credited to the right off-chain trading identity.
    bytes32 public offchainPubkey;
    mapping(address => uint256) public balances;
    mapping(address => uint256) public lockedBalances;
    mapping(bytes32 => Settlement) public settlements;

    // Field order here is deliberate, not just declaration convenience:
    // Solidity packs consecutive struct fields into one 32-byte storage
    // slot as long as they fit, only starting a fresh slot when the next
    // field wouldn't. deadline (uint40, safe until year 36812 -- no real
    // Unix timestamp gets close) + the 3 status bools + token (address)
    // total 28 bytes and share ONE slot; assignedNode and lockedAmount
    // each need a full slot of their own regardless of order (both are
    // exactly 32 bytes); counterparty gets the last slot alone since
    // nothing smaller is left to share it with. That's 4 slots instead
    // of the 6 a naive field order produces, saving 2 cold SSTOREs
    // (~40k gas) on every recordSettlement call.
    struct Settlement {
        uint40 deadline;
        bool refunded;
        bool settled;
        bool slashed;
        address token;
        bytes32 assignedNode;
        uint256 lockedAmount;
        // Recorded at commitTrade time so settleBatchWithFees can verify
        // the counterparty it's about to pay actually matches what this
        // trader committed to -- without this, a caller-supplied
        // TradeEntry.counterparty at settlement time is unverified and
        // funds could be redirected to an arbitrary address.
        address counterparty;
    }

    event Deposited(address indexed token, uint256 amount);
    event Locked(address indexed token, uint256 amount);
    event Settled(address indexed token, address indexed recipient, uint256 amount);
    event FeeDeducted(address indexed token, address indexed feeRecipient, uint256 fee);
    event Unlocked(address indexed token, uint256 amount);
    event Withdrawn(address indexed token, uint256 amount);
    event Refunded(bytes32 indexed tradeHash, address indexed token, uint256 amount);

    modifier onlyFactory() {
        require(msg.sender == factory, "Only factory can execute");
        _;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can execute");
        _;
    }

    function initialize(address _owner, address _factory, bytes32 _offchainPubkey) external {
        require(factory == address(0), "Already initialized");
        owner = _owner;
        factory = _factory;
        offchainPubkey = _offchainPubkey;
    }

    function deposit(address token, uint256 amount) external payable {
        if (token == address(0)) {
            require(msg.value == amount, "Incorrect ETH value");
            balances[address(0)] += amount;
        } else {
            require(msg.value == 0, "ETH not accepted for token deposit");
            require(
                IERC20(token).transferFrom(msg.sender, address(this), amount),
                "Token transfer failed"
            );
            balances[token] += amount;
        }
        emit Deposited(token, amount);
    }

    function lock(address token, uint256 amount) external onlyFactory {
        require(balances[token] >= amount, "Insufficient balance");
        balances[token] -= amount;
        lockedBalances[token] += amount;
        emit Locked(token, amount);
    }

    function settle(address token, address recipient, uint256 amount) external onlyFactory {
        require(lockedBalances[token] >= amount, "Insufficient locked balance");
        lockedBalances[token] -= amount;
        _transfer(token, recipient, amount);
        emit Settled(token, recipient, amount);
    }

    // Settles one or more trades from this escrow in the same token as a
    // single lockedBalances write, instead of one settleWithFee call (and
    // one lockedBalances SSTORE) per trade. SettlementFactory groups
    // same-trader-same-token trades from one settleBatchWithFees call
    // before calling this -- recipients/amounts is that group's individual
    // trade payouts (still paid out separately, since counterparties
    // differ), totalFee is the group's combined fee (all going to the same
    // feeRecipient, since fee destination is uniform for a whole
    // settleBatchWithFees call). A single-trade group (recipients.length
    // == 1) behaves identically to the old settleWithFee.
    function settleNetted(
        address token,
        address[] calldata recipients,
        uint256[] calldata amounts,
        uint256 totalFee,
        address feeRecipient
    ) external onlyFactory {
        require(recipients.length == amounts.length, "recipients/amounts length mismatch");

        uint256 totalAmount = 0;
        for (uint256 i = 0; i < amounts.length; i++) {
            totalAmount += amounts[i];
        }

        uint256 totalRequired = totalAmount + totalFee;
        require(lockedBalances[token] >= totalRequired, "Insufficient locked balance");
        lockedBalances[token] -= totalRequired;

        for (uint256 i = 0; i < recipients.length; i++) {
            _transfer(token, recipients[i], amounts[i]);
            emit Settled(token, recipients[i], amounts[i]);
        }

        if (totalFee > 0 && feeRecipient != address(0)) {
            _transfer(token, feeRecipient, totalFee);
            emit FeeDeducted(token, feeRecipient, totalFee);
        }
    }

    function recordSettlement(
        bytes32 tradeHash,
        uint256 deadline,
        bytes32 assignedNode,
        address token,
        uint256 lockedAmount,
        address counterparty
    ) external onlyFactory {
        require(settlements[tradeHash].deadline == 0, "Trade already recorded");
        require(deadline <= type(uint40).max, "Deadline exceeds uint40 range");
        settlements[tradeHash] = Settlement({
            deadline: uint40(deadline),
            refunded: false,
            settled: false,
            slashed: false,
            token: token,
            assignedNode: assignedNode,
            lockedAmount: lockedAmount,
            counterparty: counterparty
        });
    }

    function markSettlementSettled(bytes32 tradeHash) external onlyFactory {
        Settlement storage s = settlements[tradeHash];
        require(s.deadline != 0, "Trade not recorded");
        s.settled = true;
    }

    function markSettlementSlashed(bytes32 tradeHash) external onlyFactory {
        Settlement storage s = settlements[tradeHash];
        require(s.deadline != 0, "Trade not recorded");
        s.slashed = true;
    }

    function getSettlement(bytes32 tradeHash) external view returns (Settlement memory) {
        return settlements[tradeHash];
    }

    function refundAfterDeadline(bytes32 tradeHash) external onlyOwner {
        Settlement storage s = settlements[tradeHash];
        require(s.deadline > 0, "Trade not recorded");
        require(block.timestamp > s.deadline, "Deadline not passed");
        require(!s.refunded, "Already refunded");
        require(!s.settled, "Already settled");

        uint256 amount = s.lockedAmount;
        require(amount > 0, "Nothing to refund");
        require(lockedBalances[s.token] >= amount, "Insufficient locked balance");

        lockedBalances[s.token] -= amount;
        balances[s.token] += amount;
        s.refunded = true;

        emit Refunded(tradeHash, s.token, amount);
    }

    function unlock(address token, uint256 amount) external onlyFactory {
        require(lockedBalances[token] >= amount, "Insufficient locked balance");
        lockedBalances[token] -= amount;
        balances[token] += amount;
        emit Unlocked(token, amount);
    }

    function withdraw(address token, uint256 amount) external onlyOwner {
        require(balances[token] >= amount, "Insufficient balance");
        balances[token] -= amount;
        _transfer(token, owner, amount);
        emit Withdrawn(token, amount);
    }

    function _transfer(address token, address to, uint256 amount) private {
        if (token == address(0)) {
            payable(to).transfer(amount);
        } else {
            require(IERC20(token).transfer(to, amount), "Token transfer failed");
        }
    }
}
