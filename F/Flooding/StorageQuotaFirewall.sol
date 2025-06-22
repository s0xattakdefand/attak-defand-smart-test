// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Tracks and limits how many keys a user can write to a shared mapping.
 */
contract StorageQuotaFirewall {
    uint256 public maxWritesPerUser = 5;
    mapping(address => uint256) public writeCount;
    mapping(address => string[]) public userData;

    function store(string calldata value) external {
        require(writeCount[msg.sender] < maxWritesPerUser, "Storage quota exceeded");
        userData[msg.sender].push(value);
        writeCount[msg.sender]++;
    }

    function resetQuota(address user) external {
        require(msg.sender == user, "Self reset only");
        writeCount[user] = 0;
    }
}
