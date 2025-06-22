// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AuthenticatedEncryptionSimulator - Simulates authenticated encryption using hash commitment

contract AuthenticatedEncryptionSimulator {
    address public admin;

    mapping(bytes32 => bool) public committedHashes;
    mapping(bytes32 => bool) public usedHashes;

    event AuthenticatedEncryption(
        address indexed sender,
        bytes32 ciphertextHash,
        string label,
        uint256 timestamp
    );

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /// @notice Admin pre-commits encrypted data hash (ciphertext + tag)
    function commitEncryptedPayload(bytes32 ciphertextHash) external onlyAdmin {
        require(!committedHashes[ciphertextHash], "Already committed");
        committedHashes[ciphertextHash] = true;
    }

    /// @notice Verifies revealed ciphertext + tag pair by recomputing hash
    function authenticatedEncryption(bytes calldata ciphertext, bytes calldata tag, string calldata label) external {
        bytes32 hash = keccak256(abi.encodePacked(ciphertext, tag));
        require(committedHashes[hash], "No matching commitment");
        require(!usedHashes[hash], "Replay detected");

        usedHashes[hash] = true;

        emit AuthenticatedEncryption(msg.sender, hash, label, block.timestamp);
    }
}
