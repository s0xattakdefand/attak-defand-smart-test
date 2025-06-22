// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * DEFENSE TYPE:
 * Mark the sensitive function as 'internal' or 'private'
 * or add appropriate access checks if it must be public.
 */
contract SecureEncapsulation {
    uint256 public totalValue;

    // INTERNAL function can't be called externally
    function _addValue(uint256 val) internal {
        totalValue += val;
    }

    function increment() external {
        _addValue(1);
    }
}
