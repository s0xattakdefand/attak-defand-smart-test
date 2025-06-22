// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract InputSanitizer {
    uint256 public value;

    modifier safeInput(uint256 input) {
        require(input > 0 && input <= 100, "Invalid range");
        _;
    }

    function set(uint256 input) external safeInput(input) {
        value = input;
    }
}
