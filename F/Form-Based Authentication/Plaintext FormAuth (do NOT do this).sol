// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Simulates a login form with username/password stored on-chain
 * ❌ DANGEROUS — never store credentials like this
 */
contract InsecureFormAuth {
    mapping(address => string) public usernames;
    mapping(address => string) public passwords;

    function register(string calldata username, string calldata password) external {
        usernames[msg.sender] = username;
        passwords[msg.sender] = password;
    }

    function login(string calldata passwordAttempt) external view returns (bool) {
        return keccak256(bytes(passwords[msg.sender])) == keccak256(bytes(passwordAttempt));
    }
}
