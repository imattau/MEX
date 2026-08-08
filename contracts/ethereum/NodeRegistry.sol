// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract NodeRegistry {
    // Set at deploy time (see scripts/deploy.js) rather than hardcoded, so a
    // low-value test deployment (e.g. a public testnet, where faucet ETH is
    // scarce) can use a realistic minimum without needing a different
    // contract. Real deployments should still pass 10 ether.
    uint256 public immutable MIN_STAKE;
    uint256 public constant MAX_MISSED_DEADLINES = 3;
    uint256 public constant REPUTATION_SCALE = 10000;

    enum TrustLevel {
        Newcomer,
        Contributor,
        Trusted,
        Elite,
        Banned
    }

    struct NodeInfo {
        bytes32 nodePubkey;
        address operator;
        uint256 stake;
        uint256 registeredAt;
        bool active;
        uint256 slashCount;
        uint256 missedDeadlines;
        string geoRegion;
        uint32 reputationScore;
        TrustLevel trustLevel;
        uint64 lastRepUpdate;
    }

    mapping(bytes32 => NodeInfo) public nodes;
    bytes32[] public nodeList;
    uint256 public totalNodes;

    address public admin;
    address public slashingAuthority;

    event NodeRegistered(bytes32 indexed nodePubkey, address indexed operator, string geoRegion);
    event NodeSlashed(bytes32 indexed nodePubkey, uint256 amount);
    event NodePenalized(bytes32 indexed nodePubkey, uint256 penalty);
    event NodeDeactivated(bytes32 indexed nodePubkey);
    event NodeActivated(bytes32 indexed nodePubkey);
    event MissedDeadlineRecorded(bytes32 indexed nodePubkey, uint256 totalMissed);
    event NodeReputationUpdated(bytes32 indexed nodePubkey, uint32 score, TrustLevel level);

    modifier onlyNodeOperator(bytes32 nodePubkey) {
        require(nodes[nodePubkey].operator == msg.sender, "Not node operator");
        _;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier onlySlashingAuthority() {
        require(msg.sender == slashingAuthority, "Not slashing authority");
        _;
    }

    constructor(uint256 minStake_) {
        require(minStake_ > 0, "minStake must be positive");
        admin = msg.sender;
        MIN_STAKE = minStake_;
    }

    function setSlashingAuthority(address _slashingAuthority) external onlyAdmin {
        slashingAuthority = _slashingAuthority;
    }

    function transferAdmin(address newAdmin) external onlyAdmin {
        require(newAdmin != address(0), "Invalid admin");
        admin = newAdmin;
    }

    function registerNode(bytes32 nodePubkey, string calldata geoRegion) external payable {
        require(msg.value >= MIN_STAKE, "Insufficient stake");
        require(nodes[nodePubkey].registeredAt == 0, "Node already registered");

        nodes[nodePubkey] = NodeInfo({
            nodePubkey: nodePubkey,
            operator: msg.sender,
            stake: msg.value,
            registeredAt: block.timestamp,
            active: true,
            slashCount: 0,
            missedDeadlines: 0,
            geoRegion: geoRegion,
            reputationScore: 5000,
            trustLevel: TrustLevel.Newcomer,
            lastRepUpdate: uint64(block.timestamp)
        });

        nodeList.push(nodePubkey);
        totalNodes++;

        emit NodeRegistered(nodePubkey, msg.sender, geoRegion);
    }

    function updateReputation(
        bytes32 nodePubkey,
        uint32 newScore,
        TrustLevel newLevel
    ) external onlySlashingAuthority {
        NodeInfo storage node = nodes[nodePubkey];
        require(node.registeredAt > 0, "Node not registered");

        node.reputationScore = newScore;
        node.trustLevel = newLevel;
        node.lastRepUpdate = uint64(block.timestamp);

        emit NodeReputationUpdated(nodePubkey, newScore, newLevel);
    }

    function getReputation(bytes32 nodePubkey)
        external
        view
        returns (uint32 score, TrustLevel level, uint64 lastUpdate)
    {
        NodeInfo storage node = nodes[nodePubkey];
        return (node.reputationScore, node.trustLevel, node.lastRepUpdate);
    }

    // Pays the slashed amount out to `recipient` -- the party actually
    // wronged by whatever this node did (e.g. the trader who called
    // claimSlash after a missed settlement deadline) -- rather than
    // leaving it stuck in this contract's balance with no way out.
    // recipient is chosen by the slashing authority (SettlementFactory),
    // not this contract: NodeRegistry only tracks stake/reputation and
    // has no notion of trades or escrows, so it can't determine on its
    // own who was wronged.
    function slashNode(bytes32 nodePubkey, uint256 amount, address payable recipient) external onlySlashingAuthority {
        NodeInfo storage node = nodes[nodePubkey];
        require(node.active, "Node not active");
        require(node.stake >= amount, "Insufficient stake to slash");
        require(recipient != address(0), "Invalid recipient");

        node.stake -= amount;
        node.slashCount++;
        node.active = false;
        node.reputationScore = node.reputationScore / 2;

        emit NodeSlashed(nodePubkey, amount);
        emit NodeDeactivated(nodePubkey);
        emit NodeReputationUpdated(nodePubkey, node.reputationScore, node.trustLevel);

        if (node.stake < MIN_STAKE) {
            delete nodes[nodePubkey];
        }

        recipient.transfer(amount);
    }

    function recordMissedDeadline(bytes32 nodePubkey) external {
        NodeInfo storage node = nodes[nodePubkey];
        require(node.active, "Node not active");

        node.missedDeadlines++;
        emit MissedDeadlineRecorded(nodePubkey, node.missedDeadlines);

        if (node.missedDeadlines >= MAX_MISSED_DEADLINES) {
            _autoPenalize(nodePubkey);
        }
    }

    // Unlike slashNode, this penalty has no single identifiable recipient:
    // it's triggered by a cumulative missed-deadline COUNT
    // (recordMissedDeadline, callable by anyone, not tied to one trader's
    // claim), not one specific trade a specific trader can point to. The
    // penalized amount is still just decremented from node.stake here and
    // left in this contract's balance with no payout path -- the same gap
    // slashNode had until it gained a recipient, minus the part of the fix
    // that doesn't apply here (there's no single wronged party to pay).
    // Resolving this would need a shared destination (e.g. an insurance/
    // treasury pool distributed across affected traders) that doesn't
    // exist yet.
    function _autoPenalize(bytes32 nodePubkey) private {
        NodeInfo storage node = nodes[nodePubkey];
        uint256 penalty = node.stake / 2;
        node.stake -= penalty;
        node.missedDeadlines = 0;
        node.active = false;
        node.reputationScore = node.reputationScore / 2;

        emit NodePenalized(nodePubkey, penalty);
        emit NodeDeactivated(nodePubkey);
        emit NodeReputationUpdated(nodePubkey, node.reputationScore, node.trustLevel);

        if (node.stake < MIN_STAKE) {
            delete nodes[nodePubkey];
        }
    }

    function deactivateNode(bytes32 nodePubkey) external onlyNodeOperator(nodePubkey) {
        nodes[nodePubkey].active = false;
        emit NodeDeactivated(nodePubkey);
    }

    function activateNode(bytes32 nodePubkey) external onlyNodeOperator(nodePubkey) {
        require(nodes[nodePubkey].stake >= MIN_STAKE, "Stake below minimum");
        nodes[nodePubkey].active = true;
        emit NodeActivated(nodePubkey);
    }

    function withdrawStake(bytes32 nodePubkey) external onlyNodeOperator(nodePubkey) {
        NodeInfo storage node = nodes[nodePubkey];
        require(!node.active, "Must deactivate first");

        uint256 amount = node.stake;
        node.stake = 0;
        payable(node.operator).transfer(amount);
    }

    function isActiveNode(bytes32 nodePubkey) external view returns (bool) {
        return nodes[nodePubkey].active;
    }

    function getNode(bytes32 nodePubkey) external view returns (NodeInfo memory) {
        return nodes[nodePubkey];
    }

    function getNodeCount() external view returns (uint256) {
        return totalNodes;
    }

    function getNodePubkeys() external view returns (bytes32[] memory) {
        return nodeList;
    }
}
