// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ZKPasswordVerifier — Simulates ZKPP via commit-reveal with nonce and expiry

contract ZKPasswordVerifier {
    address public owner;
    mapping(address => bytes32) public commitments;
    mapping(address => bool) public verified;
    mapping(bytes32 => bool) public usedProofs;

    event PasswordCommitted(address indexed user, bytes32 commitment, uint256 expiresAt);
    event PasswordVerified(address indexed user);

    struct Commitment {
        bytes32 hash;
        uint256 expiresAt;
    }

    mapping(address => Commitment) public userCommitments;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// 🔐 Step 1: Commit hashed(password + salt + nonce) off-chain
    function commitPassword(bytes32 hash, uint256 expiresAt) external {
        require(block.timestamp < expiresAt, "Invalid expiry");
        userCommitments[msg.sender] = Commitment(hash, expiresAt);
        emit PasswordCommitted(msg.sender, hash, expiresAt);
    }

    /// ✅ Step 2: Reveal password + salt + nonce
    function revealPassword(string calldata password, bytes32 salt, bytes32 nonce) external {
        Commitment memory c = userCommitments[msg.sender];
        require(block.timestamp <= c.expiresAt, "Commitment expired");

        bytes32 proof = keccak256(abi.encodePacked(password, salt, nonce));
        require(!usedProofs[proof], "Replay detected");
        require(proof == c.hash, "Invalid proof");

        usedProofs[proof] = true;
        verified[msg.sender] = true;
        emit PasswordVerified(msg.sender);
    }

    /// 🔍 Read verification status
    function isVerified(address user) external view returns (bool) {
        return verified[user];
    }
}
