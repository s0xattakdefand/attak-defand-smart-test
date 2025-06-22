// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BufferOverflowVulnerable {
    uint256[] public data;

    function pushData(uint256 index, uint256 value) public {
        data[index] = value; // ❌ This will revert in >=0.8.x, but older versions silently overflow
    }

    function getData(uint256 index) public view returns (uint256) {
        return data[index];
    }
}
