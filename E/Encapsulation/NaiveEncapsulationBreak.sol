// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * ATTACK TYPE:
 * A contract that intended an internal function, but made it public => 
 * attacker can directly call it and break assumptions.
 */
contract NaiveEncapsulationBreak {
    uint256 public totalValue;

    // Suppose we wanted this to be 'internal' only
    function addValue(uint256 val) public {
        // ❌ Attack: we wanted an internal-only helper, 
        // but it's publicly callable, messing with contract assumptions
        totalValue += val;
    }

    function increment() external {
        // The dev only calls addValue(1) here, thinking it's the only usage
        addValue(1);
    }
}
