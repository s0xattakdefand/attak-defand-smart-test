// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title GasComplexityTest - Demonstrates O(1), O(n), O(n²) gas growth in Solidity

contract GasComplexityTest {
    uint256[] public data;

    constructor(uint256 n) {
        for (uint256 i = 0; i < n; i++) {
            data.push(i);
        }
    }

    /// O(1): Constant-time mapping lookup
    mapping(uint256 => uint256) public map;

    function constantLookup(uint256 key) external view returns (uint256) {
        return map[key];
    }

    /// O(n): Loop over all data
    function linearSum() external view returns (uint256 sum) {
        for (uint256 i = 0; i < data.length; i++) {
            sum += data[i];
        }
    }

    /// O(n²): Nested loops (dangerous at high scale)
    function quadraticSum() external view returns (uint256 sum) {
        for (uint256 i = 0; i < data.length; i++) {
            for (uint256 j = 0; j < data.length; j++) {
                sum += data[i] * data[j];
            }
        }
    }

    /// Add to data array (grows input size)
    function append(uint256 val) external {
        data.push(val);
    }
}
