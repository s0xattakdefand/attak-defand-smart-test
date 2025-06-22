// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract InsecureFragmentStorage {
    mapping(uint256 => string) public fragments;

    function store(uint256 index, string calldata data) external {
        fragments[index] = data; // Overwrites allowed!
    }

    function read(uint256 index) external view returns (string memory) {
        return fragments[index];
    }
}
