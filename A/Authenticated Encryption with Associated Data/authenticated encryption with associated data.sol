// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AEADVerifier - Simulates Authenticated Encryption with Associated Data (AEAD) verification

contract AEADVerifier {
    address public admin;

    mapping(bytes32 => bool) public committedAEAD;
    mapping(bytes32 => bool) public usedAEAD;

    event AEADVerified(
        address indexed sender,
        bytes32 indexed aeadHash,
        string aad,
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

    /// @notice Commit AEAD hash: keccak256(ciphertext || tag || aad)
    function commitAEADHash(bytes32 aeadHash) external onlyAdmin {
        require(!committedAEAD[aeadHash], "Already committed");
        committedAEAD[aeadHash] = true;
    }

    /// @notice Reveal AEAD for on-chain verification
    /// @param ciphertext Encrypted data (off-chain)
    /// @param tag AEAD tag from encryption (off-chain)
    /// @param aad Associated data (public metadata)
    /// @param label Optional label for logging (e.g., “zkLoginSession”)
    function verifyAEAD(bytes calldata ciphertext, bytes calldata tag, string calldata aad, string calldata label) external {
        bytes32 hash = keccak256(abi.encodePacked(ciphertext, tag, aad));
        require(committedAEAD[hash], "AEAD not committed");
        require(!usedAEAD[hash], "Replay detected");

        usedAEAD[hash] = true;

        emit AEADVerified(msg.sender, hash, aad, label, block.timestamp);
    }
}
