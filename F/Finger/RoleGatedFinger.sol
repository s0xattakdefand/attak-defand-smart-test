// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract RoleGatedFinger is AccessControl {
    bytes32 public constant FINGER_ROLE = keccak256("FINGER_ROLE");

    mapping(address => string) public usernames;
    mapping(address => string) public roles;

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(FINGER_ROLE, admin);
    }

    function setProfile(string calldata username, string calldata role) external {
        usernames[msg.sender] = username;
        roles[msg.sender] = role;
    }

    function finger(address user) external view onlyRole(FINGER_ROLE) returns (string memory, string memory) {
        return (usernames[user], roles[user]);
    }
}
