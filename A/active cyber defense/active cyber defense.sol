// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Active Cyber Defense Engine

contract ActiveCyberDefense {
    address public admin;
    bool public paused;
    mapping(address => bool) public blacklist;
    mapping(address => uint256) public anomalyScore;

    event AttackDetected(address indexed attacker, string reason);
    event AccessRevoked(address indexed user);
    event ContractPaused();
    event AlertRaised(address indexed user, string anomaly);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Admin only");
        _;
    }

    modifier notBlacklisted() {
        require(!blacklist[msg.sender], "Blacklisted");
        _;
    }

    modifier notPaused() {
        require(!paused, "Paused by defense system");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /// Protected action with active defense
    function protectedAction(uint256 input) external notBlacklisted notPaused {
        if (input > 1000) {
            _triggerDefense(msg.sender, "Abnormal input");
            return;
        }

        // Normal action here
    }

    /// DETECT & RESPOND
    function _triggerDefense(address attacker, string memory reason) internal {
        emit AttackDetected(attacker, reason);
        blacklist[attacker] = true;
        anomalyScore[attacker]++;
        emit AccessRevoked(attacker);

        if (anomalyScore[attacker] > 2) {
            paused = true;
            emit ContractPaused();
        }

        emit AlertRaised(attacker, reason);
    }

    /// Manual override
    function unpause() external onlyAdmin {
        paused = false;
    }

    function removeFromBlacklist(address user) external onlyAdmin {
        blacklist[user] = false;
        anomalyScore[user] = 0;
    }
}
