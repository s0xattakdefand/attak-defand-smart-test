// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract UnverifiedLookup {
    mapping(string => address) public nameToAddress;

    function register(string calldata name) external {
        nameToAddress[name] = msg.sender; // anyone can overwrite
    }

    function resolve(string calldata name) external view returns (address) {
        return nameToAddress[name];
    }
}
