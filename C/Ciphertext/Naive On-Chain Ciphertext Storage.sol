// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Naive on-chain ciphertext approach:
 * - Stores ciphertext + key, defeating the purpose of encryption.
 */
contract NaiveCiphertextStore {
    mapping(address => bytes) public storedCipher;
    mapping(address => bytes) public storedKey;

    function storeCiphertext(bytes calldata cipher, bytes calldata key) external {
        // ❌ Key is also stored on-chain, attacker sees it in plain form
        storedCipher[msg.sender] = cipher;
        storedKey[msg.sender] = key;
    }

    function readDecrypted(address user) external view returns (bytes memory) {
        // ❌ Just a naive XOR or something if we did on chain
        // Attackers can trivially decrypt since key is visible
        return storedCipher[user];
    }
}
