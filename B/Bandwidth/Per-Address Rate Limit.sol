// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PerAddressRateLimit {
    mapping(address => uint256) public lastUsed;
    uint256 public constant COOLDOWN = 30; // 30 seconds cooldown

    event ActionExecuted(address indexed user, uint256 timestamp);

    function limitedAction() public {
        require(
            block.timestamp > lastUsed[msg.sender] + COOLDOWN,
            "Action cooldown: try later"
        );

        lastUsed[msg.sender] = block.timestamp;

        emit ActionExecuted(msg.sender, block.timestamp);

        // Action logic goes here
    }

    function getTimeUntilNextAllowed() public view returns (uint256 secondsRemaining) {
        if (block.timestamp > lastUsed[msg.sender] + COOLDOWN) {
            return 0;
        } else {
            return (lastUsed[msg.sender] + COOLDOWN) - block.timestamp;
        }
    }
}
