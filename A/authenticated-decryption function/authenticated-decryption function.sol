// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AuthenticatedDecryption - Secure decryption validation via hash commitments

contract AuthenticatedDecryption {
    address public owner;

    mapping(bytes32 => bool) public committedCiphertexts;

    event DecryptionVerified(
        address indexed user,
        bytes32 indexed ciphertextHash,
        string plaintext,
        uint256 timestamp
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// @notice Commit a hash of the ciphertext (off-chain encrypted data)
    function commitCiphertext(bytes32 ciphertextHash) external onlyOwner {
        require(!committedCiphertexts[ciphertextHash], "Already committed");
        committedCiphertexts[ciphertextHash] = true;
    }

    /// @notice Authenticated decryption function — validates revealed data
    /// @param plaintext Revealed message
    /// @param secret Shared key or salt (used in original hash)
    function authenticatedDecryption(string calldata plaintext, string calldata secret) external {
        bytes32 hash = keccak256(abi.encodePacked(plaintext, secret));
        require(committedCiphertexts[hash], "Commitment not found");

        committedCiphertexts[hash] = false; // one-time use to prevent replay

        emit DecryptionVerified(msg.sender, hash, plaintext, block.timestamp);
    }
}
