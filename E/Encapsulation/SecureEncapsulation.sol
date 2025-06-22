// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SecureEncapsulation {
    uint256 public totalValue;

    // internal => can't be called externally
    function _addValue(uint256 val) internal {
        totalValue += val;
    }

    function increment() external {
        _addValue(1);
    }
}
