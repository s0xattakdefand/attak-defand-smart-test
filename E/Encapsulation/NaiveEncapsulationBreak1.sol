// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract NaiveEncapsulationBreak {
    uint256 public totalValue;

    function addValue(uint256 val) public {
        totalValue += val;
    }

    function increment() external {
        addValue(1);
    }
}
