// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title UnfilteredFinger
 * @notice Anyone can look up usernames and roles for any address.
 */
contract UnfilteredFinger {
    mapping(address => string) public usernames;
    mapping(address => string) public roles;

    constructor() {
        // Pre-load some dummy data
        usernames[msg.sender] = "admin.eth";
        roles[msg.sender] = "superuser";
    }

    function setProfile(string calldata username, string calldata role) external {
        usernames[msg.sender] = username;
        roles[msg.sender] = role;
    }

    function finger(address user) external view returns (string memory, string memory) {
        return (usernames[user], roles[user]);
    }
}
