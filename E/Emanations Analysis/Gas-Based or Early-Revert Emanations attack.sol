// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * ATTACK TYPE:
 * A function's gas usage or revert condition reveals hidden info:
 * e.g. if secret state is <some condition>, revert earlier => less gas used => attacker deduces condition
 */
contract EmanationSideChannel {
    // Suppose 'secretValue' is not directly accessible, 
    // but an attacker can glean it from how the function reverts or uses gas
    uint256 private secretValue;

    constructor(uint256 _secret) {
        secretValue = _secret;
    }

    function guessSecret(uint256 guess) external returns (bool) {
        // If guess is too high, revert early => less gas used
        if (guess > secretValue) {
            revert("Guess too high, revert quickly");
        }
        // If guess is too low, do more computations => uses more gas
        for (uint256 i = 0; i < 10000; i++) {
            // worthless computations => difference in gas usage
        }
        if (guess == secretValue) {
            return true;
        }
        return false;
    }
}
