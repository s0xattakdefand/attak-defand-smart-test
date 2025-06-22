// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title SharedSecretCommit — Commit-Reveal Pattern with Shared Secret Hashing and Replay Protection
contract SharedSecretCommit {
    address public owner;
    uint256 public commitDeadline;
    bytes32 public committedHash;
    bool public revealed;

    mapping(bytes32 => bool) public usedSecrets;

    event SecretCommitted(bytes32 indexed hash, uint256 deadline);
    event SecretRevealed(address revealer, string secret);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// Step 1: Commit secret hash (e.g., keccak256(abi.encodePacked("mysecret", salt)))
    function commitSecret(bytes32 hash, uint256 delaySeconds) external onlyOwner {
        require(committedHash == bytes32(0), "Already committed");
        committedHash = hash;
        commitDeadline = block.timestamp + delaySeconds;
        emit SecretCommitted(hash, commitDeadline);
    }

    /// Step 2: Reveal secret string + salt (off-chain computed)
    function revealSecret(string calldata secret, bytes32 salt) external {
        require(block.timestamp >= commitDeadline, "Too early");
        require(!revealed, "Already revealed");

        bytes32 hash = keccak256(abi.encodePacked(secret, salt));
        require(hash == committedHash, "Invalid secret");
        require(!usedSecrets[hash], "Secret reused");

        usedSecrets[hash] = true;
        revealed = true;

        emit SecretRevealed(msg.sender, secret);
    }

    /// Derive a shared key off-chain from secret string using HKDF or similar
}
