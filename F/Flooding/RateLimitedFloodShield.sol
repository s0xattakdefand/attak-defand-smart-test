// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Rate-limited function: Each user must wait N seconds between calls.
 */
contract RateLimitedFloodShield {
    mapping(address => uint256) public lastCall;
    uint256 public cooldown = 60; // 60 seconds

    function ping() external {
        require(block.timestamp >= lastCall[msg.sender] + cooldown, "Cooldown active");
        lastCall[msg.sender] = block.timestamp;
        // Logic
    }
}
