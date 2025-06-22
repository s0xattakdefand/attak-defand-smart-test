// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ConfidentialDataVault — Confidentiality-preserving vault using commit-reveal and hash-based proof
contract ConfidentialDataVault {
    address public owner;
    mapping(address => bytes32) public commitments;
    mapping(address => bool) public revealed;
    mapping(address => string) public decryptedLabels;

    event Committed(address indexed user, bytes32 commitment);
    event Revealed(address indexed user, string label);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// ✅ Step 1: User commits to a secret (e.g., hashed label, password)
    function commit(bytes32 hash) external {
        commitments[msg.sender] = hash;
        emit Committed(msg.sender, hash);
    }

    /// ✅ Step 2: User reveals the preimage to prove they knew it
    function reveal(string calldata label, bytes32 salt) external {
        require(!revealed[msg.sender], "Already revealed");
        bytes32 computed = keccak256(abi.encodePacked(label, salt));
        require(commitments[msg.sender] == computed, "Invalid proof");

        decryptedLabels[msg.sender] = label;
        revealed[msg.sender] = true;
        emit Revealed(msg.sender, label);
    }

    /// 🔐 View-only access for admin to see revealed data
    function getRevealedLabel(address user) external view onlyOwner returns (string memory) {
        return decryptedLabels[user];
    }
}
