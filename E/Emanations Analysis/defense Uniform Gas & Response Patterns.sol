// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * DEFENSE TYPE:
 * Make all branches consume roughly the same gas 
 * or always revert the same way => no early exit revelations.
 */
contract UniformResponse {
    uint256 private secretValue;

    constructor(uint256 _secret) {
        secretValue = _secret;
    }

    function guessSecret(uint256 guess) external returns (bool) {
        // Force same structure => no early revert or obviously different gas usage
        uint256 local = secretValue; // copy to reduce differences
        bool correct = false;

        // We do some dummy loops always, no matter guess
        for (uint256 i = 0; i < 10000; i++) {
            // worthless computation => uniform for any path
        }

        // Compare after the loop
        if (guess == local) {
            correct = true;
        }

        // Always do an event or revert style
        // Instead of different messages, revert with a single message 
        // or always return a bool
        return correct;
    }
}
