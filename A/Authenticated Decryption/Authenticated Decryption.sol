// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AuthenticatedDecryptionVerifier - Simulates authenticated decryption using hash commitment

contract AuthenticatedDecryptionVerifier {
    address public admin;

    mapping(bytes32 => bool) public usedCommitments;

    event AuthenticatedDecryption(
        address indexed user,
        bytes32 ciphertextHash,
        string decryptedMessage,
        uint256 timestamp
    );

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /// @notice Commit to ciphertext hash (representing encrypted payload)
    function commitCiphertext(bytes32 ciphertextHash) external onlyAdmin {
        require(!usedCommitments[ciphertextHash], "Already committed");
        usedCommitments[ciphertextHash] = true;
    }

    /// @notice Verify authenticated decryption (simulated)
    /// @param plaintext The revealed message
    /// @param secret The decryption key/salt used to hash
    function verifyDecryption(string calldata plaintext, string calldata secret) external {
        bytes32 reconstructedHash = keccak256(abi.encodePacked(plaintext, secret));
        require(usedCommitments[reconstructedHash], "No matching ciphertext commitment");

        emit AuthenticatedDecryption(msg.sender, reconstructedHash, plaintext, block.timestamp);
        usedCommitments[reconstructedHash] = false; // One-time use
    }
}
