// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract NoFilter {
    uint256 public sensitiveValue;

    // Anyone can call this without restriction!
    function updateSensitiveValue(uint256 newValue) external {
        sensitiveValue = newValue;
    }
}
