// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Another approach to encapsulate logic:
 * Put it in an internal library => no external calls, 
 * only the contract can call it.
 */
library InternalLib {
    function addVal(uint256 current, uint256 val) internal pure returns (uint256) {
        return current + val;
    }
}

contract LibraryEncapsulation {
    using InternalLib for uint256;

    uint256 public totalValue;

    function increment() external {
        // Only the contract can do the library call
        totalValue = totalValue.addVal(1);
    }
}
