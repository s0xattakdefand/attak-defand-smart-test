// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RateLimitedFinger {
    mapping(address => string) public usernames;
    mapping(address => string) public roles;
    mapping(address => uint256) public lastFingerTime;

    uint256 public cooldown = 60; // 60 seconds

    function setProfile(string calldata username, string calldata role) external {
        usernames[msg.sender] = username;
        roles[msg.sender] = role;
    }

    function finger(address user) external returns (string memory, string memory) {
        require(block.timestamp >= lastFingerTime[msg.sender] + cooldown, "Rate limited");
        lastFingerTime[msg.sender] = block.timestamp;
        return (usernames[user], roles[user]);
    }
}
