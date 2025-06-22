// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BotDetectorFirewall {
    mapping(address => uint256) public lastCallBlock;
    mapping(address => bool) public flagged;
    uint256 public threshold = 3;

    modifier antiBot() {
        if (block.number == lastCallBlock[msg.sender]) {
            flagged[msg.sender] = true;
            revert("Bot-like behavior blocked");
        }
        _;
        lastCallBlock[msg.sender] = block.number;
    }

    function accessProtectedArea() external antiBot {
        // Success: Not flagged
    }

    function isFlagged(address user) external view returns (bool) {
        return flagged[user];
    }
}
