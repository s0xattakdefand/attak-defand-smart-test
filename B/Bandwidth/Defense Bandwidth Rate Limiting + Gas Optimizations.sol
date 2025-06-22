// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BandwidthControlled {
    mapping(address => uint256) public lastAccess;
    uint256 public constant RATE_LIMIT = 60; // 60 seconds

    string[] public logs;

    modifier rateLimit() {
        require(block.timestamp > lastAccess[msg.sender] + RATE_LIMIT, "Try later");
        lastAccess[msg.sender] = block.timestamp;
        _;
    }

    function submitLog(string memory message) public rateLimit {
        logs.push(message); // controlled interaction rate
    }

    function getLogCount() public view returns (uint256) {
        return logs.length;
    }
}
