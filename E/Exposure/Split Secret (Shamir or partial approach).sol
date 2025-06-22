// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Another approach: 
 * We store partial shares of a secret if we want multiple parties to combine them off-chain,
 * but no single party can reconstruct on-chain alone.
 */
contract SplitSecretStorage {
    // For demonstration, we keep multiple shares
    bytes32[] public shares;

    constructor(bytes32[] memory _shares) {
        // each share is a partial piece of the overall secret (like Shamir's Secret Sharing)
        for (uint256 i = 0; i < _shares.length; i++) {
            shares.push(_shares[i]);
        }
    }
}
