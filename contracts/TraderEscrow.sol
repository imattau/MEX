// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TraderEscrow {
    address public factory;
    address public owner;
    mapping(address => uint256) public balances;
    mapping(address => uint256) public lockedBalances;

    event Deposited(address indexed token, uint256 amount);
    event Locked(address indexed token, uint256 amount);
    event Settled(address indexed token, address indexed recipient, uint256 amount);
    event Unlocked(address indexed token, uint256 amount);
    event Withdrawn(address indexed token, uint256 amount);

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
            // In a production system, we would transfer tokens from msg.sender
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
        if (token == address(0)) {
            payable(recipient).transfer(amount);
        } else {
            // Transfer ERC20 token to recipient
        }
        emit Settled(token, recipient, amount);
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
        if (token == address(0)) {
            payable(owner).transfer(amount);
        } else {
            // Transfer ERC20 token to owner
        }
        emit Withdrawn(token, amount);
    }
}
