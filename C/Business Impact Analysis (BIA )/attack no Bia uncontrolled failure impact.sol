// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * No BIA => All modules are equal
 * => If a critical module fails, the protocol doesn't know how to respond or prioritize
 */
contract NoBIA {
    bool public vaultOperational;
    bool public analyticsOperational;

    constructor() {
        vaultOperational = true;
        analyticsOperational = true;
    }

    function markVaultDown() external {
        // ❌ Anyone can mark the vault down, no plan or priority
        vaultOperational = false;
    }

    function markAnalyticsDown() external {
        analyticsOperational = false;
    }

    // The project has no concept of which one is critical => no priority
}
