// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ConfidentialKeyRegistry — Tracks public confidentiality keys and supports secure access policies
contract ConfidentialKeyRegistry {
    address public owner;

    mapping(address => bytes32) public pubKeyCommitments; // e.g., keccak256(ECIES pubkey or derived key)
    mapping(address => bool) public authorizedReaders;

    event PublicKeyRegistered(address indexed user, bytes32 commitment);
    event ReaderAuthorized(address indexed reader);
    event ReaderRevoked(address indexed reader);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// 🔐 Users register commitment to their public confidentiality key
    function registerPublicKey(bytes32 keyCommitment) external {
        pubKeyCommitments[msg.sender] = keyCommitment;
        emit PublicKeyRegistered(msg.sender, keyCommitment);
    }

    /// ✅ Admin authorizes specific contracts/users to access decrypted data off-chain
    function authorizeReader(address reader) external onlyOwner {
        authorizedReaders[reader] = true;
        emit ReaderAuthorized(reader);
    }

    function revokeReader(address reader) external onlyOwner {
        authorizedReaders[reader] = false;
        emit ReaderRevoked(reader);
    }

    /// View function to verify if access to decrypted output is allowed
    function isReaderAuthorized(address reader) external view returns (bool) {
        return authorizedReaders[reader];
    }

    /// Get registered pubkey hash (used off-chain for encryption or KMS query)
    function getPublicKeyCommitment(address user) external view returns (bytes32) {
        return pubKeyCommitments[user];
    }
}
