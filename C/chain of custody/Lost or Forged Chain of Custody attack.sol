// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * A naive contract that tries to track custody but
 * does not immutably record or enforce it.
 */
contract NaiveCustody {
    mapping(bytes32 => address) public currentHolder; // item -> holder

    function setHolder(bytes32 itemId, address holder) external {
        // ❌ Anyone can overwrite the holder, no event log or signature check
        currentHolder[itemId] = holder;
    }

    function getHolder(bytes32 itemId) external view returns (address) {
        return currentHolder[itemId];
    }
}
