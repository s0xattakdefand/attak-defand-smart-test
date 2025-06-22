// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title InteractionFrequencyController — Restricts how often users/functions can be called
contract InteractionFrequencyController {
    address public owner;
    uint256 public globalCooldown = 10 minutes;
    uint256 public userCooldown = 5 minutes;
    uint256 public lastGlobalInteraction;

    mapping(address => uint256) public lastUserInteraction;

    event ActionTriggered(address indexed user, uint256 timestamp);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier enforceGlobalCooldown() {
        require(
            block.timestamp >= lastGlobalInteraction + globalCooldown,
            "Global rate limit active"
        );
        _;
        lastGlobalInteraction = block.timestamp;
    }

    modifier enforceUserCooldown() {
        require(
            block.timestamp >= lastUserInteraction[msg.sender] + userCooldown,
            "User cooldown active"
        );
        _;
        lastUserInteraction[msg.sender] = block.timestamp;
    }

    constructor() {
        owner = msg.sender;
        lastGlobalInteraction = block.timestamp - globalCooldown;
    }

    /// 🔐 Function limited by both global + per-user cooldown
    function triggerAction() external enforceGlobalCooldown enforceUserCooldown {
        emit ActionTriggered(msg.sender, block.timestamp);
        // Insert sensitive logic here
    }

    /// 🔧 Adjust cooldowns
    function setCooldowns(uint256 globalDelay, uint256 userDelay) external onlyOwner {
        globalCooldown = globalDelay;
        userCooldown = userDelay;
    }

    /// 🔍 View time left before interaction allowed
    function getTimeLeft(address user) external view returns (uint256 userWait, uint256 globalWait) {
        userWait = block.timestamp < lastUserInteraction[user] + userCooldown
            ? (lastUserInteraction[user] + userCooldown - block.timestamp)
            : 0;
        globalWait = block.timestamp < lastGlobalInteraction + globalCooldown
            ? (lastGlobalInteraction + globalCooldown - block.timestamp)
            : 0;
    }
}
