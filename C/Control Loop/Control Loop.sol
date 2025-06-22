// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ControlLoopManager — Demonstrates basic control loops for access and risk enforcement
contract ControlLoopManager {
    address public owner;
    bool public paused;

    mapping(address => bool) public authorizedUsers;
    mapping(address => uint256) public riskScore;
    address[] public monitoredUsers;

    event Paused(bool status);
    event RiskDetected(address user, uint256 score);
    event UserDeauthorized(address user);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "System paused");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function authorizeUser(address user) external onlyOwner {
        authorizedUsers[user] = true;
        monitoredUsers.push(user);
    }

    function setRiskScore(address user, uint256 score) external onlyOwner {
        riskScore[user] = score;
        emit RiskDetected(user, score);
    }

    /// 🔁 Control Loop: Batch enforcement based on risk threshold
    function runRiskControlLoop(uint256 maxRiskAllowed) external onlyOwner {
        for (uint256 i = 0; i < monitoredUsers.length; i++) {
            address user = monitoredUsers[i];
            if (riskScore[user] > maxRiskAllowed && authorizedUsers[user]) {
                authorizedUsers[user] = false;
                emit UserDeauthorized(user);
            }
        }
    }

    /// 🔁 Feedback Control: Auto-pause if any user exceeds hardcoded threshold
    function runStatusFeedbackLoop(uint256 criticalRiskThreshold) external onlyOwner {
        for (uint256 i = 0; i < monitoredUsers.length; i++) {
            if (riskScore[monitoredUsers[i]] >= criticalRiskThreshold) {
                paused = true;
                emit Paused(true);
                return;
            }
        }
        paused = false;
        emit Paused(false);
    }

    /// Protected function
    function criticalAction() external whenNotPaused returns (string memory) {
        require(authorizedUsers[msg.sender], "Not authorized");
        return "Action allowed under loop-controlled conditions";
    }
}
