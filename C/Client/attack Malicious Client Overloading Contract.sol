// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * A naive contract that processes user actions with no limit or cost.
 * Attack: A malicious client calls 'processAction' infinitely => DoS or large gas usage
 */
contract ClientOverload {
    uint256 public actionCount;

    function processAction() external {
        // ❌ no rate limiting or cost, any client can spam
        actionCount++;
    }
}
