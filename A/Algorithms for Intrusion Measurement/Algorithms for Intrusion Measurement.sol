// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AIMonitor — Algorithms for Intrusion Measurement in Web3 contracts
contract AIMonitor {
    address public admin;

    struct IntrusionEvent {
        address actor;
        string metric;        // e.g., "entropy", "replay", "fallback"
        uint256 score;        // risk score (0–100+)
        string details;
        uint256 timestamp;
    }

    IntrusionEvent[] public events;
    mapping(address => uint256) public totalScore;

    event IntrusionLogged(address indexed actor, string metric, uint256 score);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function logEvent(address actor, string calldata metric, uint256 score, string calldata details) external onlyAdmin {
        events.push(IntrusionEvent(actor, metric, score, details, block.timestamp));
        totalScore[actor] += score;
        emit IntrusionLogged(actor, metric, score);
    }

    function getEvent(uint256 id) external view returns (IntrusionEvent memory) {
        return events[id];
    }

    function getRiskLevel(address actor) external view returns (string memory level) {
        uint256 s = totalScore[actor];
        if (s > 200) return "SEVERE";
        if (s > 100) return "MODERATE";
        if (s > 50) return "LOW";
        return "NORMAL";
    }

    function totalEvents() external view returns (uint256) {
        return events.length;
    }
}
