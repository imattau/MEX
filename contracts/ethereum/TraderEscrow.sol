// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract TraderEscrow {
    address public factory;
    address public owner;
    mapping(address => uint256) public balances;
    mapping(address => uint256) public lockedBalances;
    mapping(bytes32 => Settlement) public settlements;

    struct Settlement {
        uint256 deadline;
        bool refunded;
        bool settled;
        bool slashed;
        bytes32 assignedNode;
        address token;
        uint256 lockedAmount;
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

    function initialize(address _owner, address _factory) external {
        require(factory == address(0), "Already initialized");
        owner = _owner;
        factory = _factory;
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

    function settleWithFee(
        address token,
        address recipient,
        uint256 amount,
        uint256 fee,
        address feeRecipient
    ) external onlyFactory {
        uint256 totalRequired = amount + fee;
        require(lockedBalances[token] >= totalRequired, "Insufficient locked balance");
        lockedBalances[token] -= totalRequired;

        _transfer(token, recipient, amount);

        if (fee > 0 && feeRecipient != address(0)) {
            _transfer(token, feeRecipient, fee);
            emit FeeDeducted(token, feeRecipient, fee);
        }

        emit Settled(token, recipient, amount);
    }

    function recordSettlement(
        bytes32 tradeHash,
        uint256 deadline,
        bytes32 assignedNode,
        address token,
        uint256 lockedAmount
    ) external onlyFactory {
        require(settlements[tradeHash].deadline == 0, "Trade already recorded");
        settlements[tradeHash] = Settlement({
            deadline: deadline,
            refunded: false,
            settled: false,
            slashed: false,
            assignedNode: assignedNode,
            token: token,
            lockedAmount: lockedAmount
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
