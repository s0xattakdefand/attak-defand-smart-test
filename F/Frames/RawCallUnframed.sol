// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RawCallUnframed {
    mapping(address => string) public dataStore;

    function store(string calldata data) external {
        dataStore[msg.sender] = data; // No metadata, auth, or replay protection
    }
}
