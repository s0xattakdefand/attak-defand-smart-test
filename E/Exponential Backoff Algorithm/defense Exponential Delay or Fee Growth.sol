// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * DEFENSE TYPE:
 * Each repeated call from the same user requires an exponentially increasing 
 * wait time or fee, simulating exponential backoff.
 */
contract ExponentialBackoffContract {
    mapping(address => uint256) public attemptCount;
    mapping(address => uint256) public nextAllowedTime;

    uint256 public baseDelay = 60; // 1 minute
    // factor for exponent => e.g. 2 => double each time
    uint256 public backoffFactor = 2;

    event ActionDone(address indexed user, uint256 attempt);

    function setBaseDelay(uint256 delaySec) external {
        // In real usage, onlyOwner
        baseDelay = delaySec;
    }

    function setBackoffFactor(uint256 factor) external {
        // In real usage, onlyOwner
        backoffFactor = factor;
    }

    function doAction() external {
        // 1) Check current time
        require(block.timestamp >= nextAllowedTime[msg.sender], "Must wait longer");
        attemptCount[msg.sender]++;

        // 2) Calculate new wait time
        // wait = baseDelay * (backoffFactor ^ attemptCount)
        // we do a quick exponent approach
        uint256 wait = baseDelay * (backoffFactor ** (attemptCount[msg.sender] - 1));
        nextAllowedTime[msg.sender] = block.timestamp + wait;

        emit ActionDone(msg.sender, attemptCount[msg.sender]);
    }
}
