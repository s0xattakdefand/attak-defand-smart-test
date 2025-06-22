// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Blind logic approach:
 * The contract never does user-supplied branching 
 * that reveals internal state. 
 */
contract BlindLogicExample {
    uint256 private secret;

    constructor(uint256 _secret) {
        secret = _secret;
    }

    function checkSecret(uint256 guess) external pure returns (bool) {
        // We do a dummy approach that doesn't read 'secret'
        // or does so in a uniform way. 
        // For demonstration, we just always do the same steps 
        // (In real usage, you'd do something more advanced to keep uniformity).
        guess; // no different path for big/small
        return false; // or always false
    }
}
