// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SpoofableNameRegistry {
    mapping(string => address) public nameToAddr;

    function register(string calldata name) external {
        nameToAddr[name] = msg.sender; // No collision or validation
    }

    function resolve(string calldata name) external view returns (address) {
        return nameToAddr[name];
    }
}
