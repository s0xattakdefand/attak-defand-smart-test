// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Role Drift, Enforcement Miss, Wildcard Role
/// Defense Types: Modifier Guards, Central Role Mapping, Audit Logs

contract AccessControlMechanism {
    address public root;

    enum Role { NONE, VIEWER, OPERATOR, ADMIN }

    mapping(address => Role) public userRoles;

    event RoleAssigned(address indexed user, Role role);
    event AccessGranted(address indexed user, string action);
    event AttackDetected(address indexed attacker, string reason);

    constructor() {
        root = msg.sender;
        userRoles[msg.sender] = Role.ADMIN;
        emit RoleAssigned(msg.sender, Role.ADMIN);
    }

    modifier onlyRole(Role required) {
        if (userRoles[msg.sender] < required) {
            emit AttackDetected(msg.sender, "ACM role violation");
            revert("Access denied: insufficient role");
        }
        _;
    }

    /// DEFENSE: Assign user role
    function assignRole(address user, Role role) external onlyRole(Role.ADMIN) {
        userRoles[user] = role;
        emit RoleAssigned(user, role);
    }

    /// DEFENSE: Protected action
    function performAdminAction() external onlyRole(Role.ADMIN) {
        emit AccessGranted(msg.sender, "performAdminAction");
    }

    function performOperatorAction() external onlyRole(Role.OPERATOR) {
        emit AccessGranted(msg.sender, "performOperatorAction");
    }

    /// ATTACK: Call without enforcement
    function attackUnprotectedAccess() external {
        emit AttackDetected(msg.sender, "Simulated unguarded action");
        revert("Attack blocked");
    }

    /// VIEW: Get user role
    function getUserRole(address user) external view returns (Role) {
        return userRoles[user];
    }
}
