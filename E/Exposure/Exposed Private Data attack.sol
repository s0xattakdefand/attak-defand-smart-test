// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * ATTACK TYPE:
 * Storing a private key or sensitive data in a public state variable => 
 * trivially exposed in block explorers, leading to immediate compromise.
 */
contract ExposedPrivateKey {
    // ❌ Attack: Developer incorrectly puts secret or private key on chain
    bytes32 public secretKey;  

    constructor(bytes32 _secretKey) {
        secretKey = _secretKey; // fully exposed
    }

    function doSecureAction() external {
        // The contract attempts to use 'secretKey' for some encryption or signing
        // But it's worthless as it's publicly visible
    }
}
