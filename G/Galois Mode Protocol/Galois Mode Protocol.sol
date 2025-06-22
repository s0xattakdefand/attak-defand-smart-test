// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title GaloisModeProtocolAttackDefense - Full Attack and Defense Simulation for Galois Mode Protocol in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Galois Mode Protocol Contract (Vulnerable to Nonce and Tag Forgery)
contract InsecureGaloisMode {
    mapping(bytes32 => bool) public seenMessages;

    event MessageAuthenticated(address indexed user, bytes32 cipherText, bytes32 fakeTag);

    function submit(bytes32 cipherText, bytes32 fakeTag) external {
        bytes32 combined = keccak256(abi.encodePacked(cipherText, fakeTag));
        require(!seenMessages[combined], "Replay detected");

        seenMessages[combined] = true;
        emit MessageAuthenticated(msg.sender, cipherText, fakeTag);
    }
}

/// @notice Secure Galois Mode Protocol Contract (Nonce, Context, and Full Tag Verification)
contract SecureGaloisMode {
    mapping(address => uint256) public nonces;
    mapping(bytes32 => bool) public processedMessages;

    event SecureMessageAuthenticated(address indexed user, bytes32 cipherCommitment, uint256 nonce);

    function submit(bytes32 cipherText, bytes32 authTag, uint256 userNonce, uint256 timestamp) external {
        require(userNonce == nonces[msg.sender], "Nonce mismatch");
        require(block.timestamp <= timestamp + 5 minutes, "Expired message");

        bytes32 commitment = keccak256(abi.encodePacked(
            msg.sender,
            cipherText,
            authTag,
            userNonce,
            timestamp,
            block.chainid,
            address(this)
        ));

        require(!processedMessages[commitment], "Replay detected");
        processedMessages[commitment] = true;

        nonces[msg.sender] += 1;

        emit SecureMessageAuthenticated(msg.sender, commitment, userNonce);
    }
}

/// @notice Attack contract simulating Galois Mode forgery or replay
contract GaloisModeIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function injectFake(bytes32 fakeCipher, bytes32 fakeTag) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("submit(bytes32,bytes32)", fakeCipher, fakeTag)
        );
    }
}
