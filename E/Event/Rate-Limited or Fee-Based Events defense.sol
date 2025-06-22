// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * DEFENSE TYPE:
 * A contract that charges a small fee or imposes a cooldown 
 * before event emission => prevents indefinite spam or large data usage.
 */
contract SafeEventEmitter {
    event LimitedMessage(address indexed user, string message);

    mapping(address => uint256) public lastEmitTime;
    uint256 public fee = 0.001 ether;
    uint256 public cooldown = 60; // 1 minute

    function setFee(uint256 newFee) external {
        // In real usage, onlyOwner or AccessControl
        fee = newFee;
    }

    function setCooldown(uint256 newCooldown) external {
        cooldown = newCooldown;
    }

    function emitSafeMessage(string calldata msgData) external payable {
        require(msg.value >= fee, "Insufficient fee");
        require(block.timestamp >= lastEmitTime[msg.sender] + cooldown, "Cooldown active");

        lastEmitTime[msg.sender] = block.timestamp;
        emit LimitedMessage(msg.sender, msgData);
    }
}
