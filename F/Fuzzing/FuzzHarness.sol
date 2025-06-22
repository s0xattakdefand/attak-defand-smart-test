// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * A mock contract vulnerable to fuzzing-based input abuse.
 */
contract FuzzHarness {
    uint256 public counter;

    function update(uint256 input) external {
        require(input < 1000, "Too large"); // Basic guard
        counter += input;
        require(counter != 9999, "Fuzz crash triggered"); // ❌ Bug
    }
}
