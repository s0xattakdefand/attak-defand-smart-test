// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableAlgorithm {
    uint256[] public values;

    // ❌ Inefficient insertion sort (can be DoSed)
    function sortAndStore(uint256[] memory input) public {
        for (uint256 i = 0; i < input.length; i++) {
            for (uint256 j = i + 1; j < input.length; j++) {
                if (input[i] > input[j]) {
                    (input[i], input[j]) = (input[j], input[i]);
                }
            }
        }
        values = input;
    }
}
