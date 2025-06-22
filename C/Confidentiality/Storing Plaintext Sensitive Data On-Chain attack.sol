// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Attack scenario:
 * This contract openly stores user secrets or personal data. 
 * Anyone scanning the blockchain can read it => zero confidentiality.
 */
contract NaivePlaintextStore {
    mapping(address => string) public userSecrets;

    function storeSecret(string calldata secret) external {
        // ❌ Attack: data is publicly stored, no encryption/hashing
        userSecrets[msg.sender] = secret;
    }

    function readSecret(address user) external view returns (string memory) {
        return userSecrets[user];
    }
}
