// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RateLimiter {
    mapping(address => uint256) public lastAccess;
    uint256 public constant COOLDOWN = 60; // 60 seconds

    event AccessGranted(address indexed user, uint256 timestamp);

    modifier rateLimited() {
        require(
            block.timestamp > lastAccess[msg.sender] + COOLDOWN,
            "Rate limit: wait before retry"
        );
        _;
        lastAccess[msg.sender] = block.timestamp;
    }

    function performSensitiveAction() public rateLimited {
        // Protected logic
        emit AccessGranted(msg.sender, block.timestamp);
    }

    function timeUntilNextAccess(address user) public view returns (uint256 secondsRemaining) {
        uint256 nextTime = lastAccess[user] + COOLDOWN;
        if (block.timestamp >= nextTime) return 0;
        return nextTime - block.timestamp;
    }
}
