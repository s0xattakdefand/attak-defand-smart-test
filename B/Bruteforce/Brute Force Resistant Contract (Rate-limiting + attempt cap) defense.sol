// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BruteForceDefender {
    bytes32 private secretHash;
    uint256 public maxAttempts = 5;
    mapping(address => uint256) public attempts;
    mapping(address => uint256) public lastAttemptTime;
    uint256 public cooldown = 60; // seconds

    constructor(string memory _secret) {
        secretHash = keccak256(abi.encodePacked(_secret));
    }

    function guessProtected(string memory guessWord) public view returns (bool) {
        return keccak256(abi.encodePacked(guessWord)) == secretHash;
    }

    function guessWithLimits(string memory guessWord) public returns (bool) {
        require(block.timestamp > lastAttemptTime[msg.sender] + cooldown, "Cooldown active");
        require(attempts[msg.sender] < maxAttempts, "Too many attempts");

        attempts[msg.sender]++;
        lastAttemptTime[msg.sender] = block.timestamp;

        return guessProtected(guessWord);
    }

    function resetAttempts(address user) public {
        // In production: onlyOwner or time-expired auto-reset
        attempts[user] = 0;
    }
}
