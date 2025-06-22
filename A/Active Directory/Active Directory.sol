// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Web3 Active Directory (Access Control + Group Registry)

contract ActiveDirectory {
    address public admin;

    enum Role { NONE, VIEWER, OPERATOR, ADMIN }

    mapping(address => Role) public roles;
    mapping(string => mapping(address => bool)) public groupMembers;

    event RoleAssigned(address indexed user, Role role);
    event RoleRevoked(address indexed user);
    event GroupJoined(address indexed user, string group);
    event GroupLeft(address indexed user, string group);
    event AttackDetected(address indexed attacker, string reason);

    modifier onlyAdmin() {
        require(roles[msg.sender] == Role.ADMIN, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
        roles[admin] = Role.ADMIN;
    }

    // Assign roles
    function assignRole(address user, Role role) external onlyAdmin {
        roles[user] = role;
        emit RoleAssigned(user, role);
    }

    function revokeRole(address user) external onlyAdmin {
        delete roles[user];
        emit RoleRevoked(user);
    }

    // Group membership
    function joinGroup(string calldata group) external {
        groupMembers[group][msg.sender] = true;
        emit GroupJoined(msg.sender, group);
    }

    function leaveGroup(string calldata group) external {
        delete groupMembers[group][msg.sender];
        emit GroupLeft(msg.sender, group);
    }

    // Enforcement
    modifier onlyRole(Role required) {
        if (roles[msg.sender] < required) {
            emit AttackDetected(msg.sender, "Unauthorized role usage");
            revert("Access denied");
        }
        _;
    }

    modifier onlyGroup(string memory group) {
        if (!groupMembers[group][msg.sender]) {
            emit AttackDetected(msg.sender, "Unauthorized group access");
            revert("Not part of group");
        }
        _;
    }

    // Example: Protected functions
    function performAdminAction() external onlyRole(Role.ADMIN) {
        // admin logic here
    }

    function performGroupAction(string calldata group) external onlyGroup(group) {
        // group-restricted logic
    }
}
