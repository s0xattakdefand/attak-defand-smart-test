// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FlatNameRegistry {
    mapping(string => address) public names;

    function register(string calldata name) external {
        names[name] = msg.sender;
    }

    function resolve(string calldata name) external view returns (address) {
        return names[name];
    }
}
