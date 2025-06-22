// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title GaloisCounterModeAttackDefense - Full Attack and Defense Simulation for GCM Properties in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Simulated Insecure GCM-Like Contract (No Nonce Control, No Tag Validation)
contract InsecureGCM {
    mapping(address => bytes32) public userCommitments;

    event EncryptedDataSubmitted(address indexed user, bytes32 ciphertext, bytes32 fakeTag);

    function submitEncrypted(bytes32 ciphertext, bytes32 fakeTag) external {
        // BAD: No nonce tracking, no tag verification
        userCommitments[msg.sender] = keccak256(abi.encodePacked(ciphertext, fakeTag));
        emit EncryptedDataSubmitted(msg.sender, ciphertext, fakeTag);
    }

    function retrieveCommitment(address user) external view returns (bytes32) {
        return userCommitments[user];
    }
}

/// @notice Secure GCM-Like Contract (Nonce Binding, Tag Validation, Replay Protection)
contract SecureGCM {
    address public immutable admin;
    mapping(address => bytes32) public userCommitments;
    mapping(address => uint256) public nonces;

    event EncryptedDataCommitted(address indexed user, bytes32 commitment);

    constructor() {
        admin = msg.sender;
    }

    function submitEncrypted(bytes32 ciphertext, bytes32 authTag, uint256 userNonce) external {
        require(userNonce == nonces[msg.sender], "Invalid or replayed nonce");

        bytes32 expectedCommitment = keccak256(abi.encodePacked(msg.sender, userNonce, ciphertext, authTag));

        userCommitments[msg.sender] = expectedCommitment;
        nonces[msg.sender] += 1; // Increment nonce to prevent reuse

        emit EncryptedDataCommitted(msg.sender, expectedCommitment);
    }

    function verifyCommitment(address user, bytes32 revealedCiphertext, bytes32 revealedTag, uint256 revealedNonce) external view returns (bool) {
        bytes32 expected = keccak256(abi.encodePacked(user, revealedNonce, revealedCiphertext, revealedTag));
        return userCommitments[user] == expected;
    }
}

/// @notice Attack contract simulating GCM nonce replay or tag forgery
contract GCMIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function injectFakeData(bytes32 fakeCiphertext, bytes32 fakeTag) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("submitEncrypted(bytes32,bytes32)", fakeCiphertext, fakeTag)
        );
    }
}
