// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract NoCostCheck {
    function trigger() external {
        // Anyone can execute — no check for benefit
        // May drain gas, trigger side effects, or spam logs
        for (uint256 i = 0; i < 1000; i++) {
            emit Triggered(i);
        }
    }

    event Triggered(uint256 n);
}
