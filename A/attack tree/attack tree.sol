// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AttackTreeMonitor - Monitors and scores attack paths based on event sequences (attack tree)

contract AttackTreeMonitor {
    address public admin;

    struct AttackNode {
        string label;
        uint256 weight; // threat level
        bool terminal;  // goal state
    }

    mapping(bytes32 => AttackNode) public nodes;
    mapping(address => bytes32[]) public actorPaths;
    mapping(address => uint256) public threatScore;

    event NodeTriggered(address indexed actor, bytes32 nodeId, string label, uint256 score);
    event ThreatMitigated(address indexed actor, uint256 score);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerNode(bytes32 nodeId, string calldata label, uint256 weight, bool terminal) external onlyAdmin {
        nodes[nodeId] = AttackNode(label, weight, terminal);
    }

    function triggerNode(bytes32 nodeId) external {
        require(nodes[nodeId].weight > 0, "Unknown node");

        actorPaths[msg.sender].push(nodeId);
        threatScore[msg.sender] += nodes[nodeId].weight;

        emit NodeTriggered(msg.sender, nodeId, nodes[nodeId].label, threatScore[msg.sender]);

        if (nodes[nodeId].terminal) {
            _mitigateThreat(msg.sender);
        }
    }

    function _mitigateThreat(address actor) internal {
        // Mitigation logic: revoke role, lock account, etc.
        emit ThreatMitigated(actor, threatScore[actor]);
    }

    function getPath(address actor) external view returns (bytes32[] memory) {
        return actorPaths[actor];
    }

    function getScore(address actor) external view returns (uint256) {
        return threatScore[actor];
    }
}
