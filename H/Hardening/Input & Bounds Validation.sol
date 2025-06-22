// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract HardenedInput {
    uint256 public value;

    function setValue(uint256 newValue) external {
        require(newValue > 0 && newValue < 1_000_000, "Out of bounds");
        value = newValue;
    }
}
