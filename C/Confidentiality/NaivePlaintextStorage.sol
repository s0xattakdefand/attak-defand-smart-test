// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * ATTACK TYPE:
 * Naive approach that stores sensitive data in plaintext on-chain,
 * exposing it to anyone who scans the blockchain.
 */
contract NaivePlaintextStorage {
    mapping(address => string) public secrets;

    function storeSecret(string calldata secret) external {
        // ❌ Attack: data is public forever on the ledger
        secrets[msg.sender] = secret;
    }

    function readSecret(address user) external view returns (string memory) {
        return secrets[user];
    }
}
