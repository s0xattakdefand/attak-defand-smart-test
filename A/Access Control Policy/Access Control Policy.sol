// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Bypass, Drift, Wildcard Grant
/// Defense Types: Explicit Map, Modifier Guard, Audit Trail

contract AccessControlPolicy {
    address public admin;

    enum Role { NONE, USER, OPERATOR, ADMIN }

    // Maps: address → Role, actionId → Role
    mapping(address => Role) public userRoles;
    mapping(string => Role) public actionPolicy;

    event RoleAssigned(address indexed user, Role role);
    event PolicyDefined(string indexed actionId, Role requiredRole);
    event ActionExecuted(address indexed user, string actionId);
    event AttackDetected(address indexed attacker, string reason);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
        userRoles[msg.sender] = Role.ADMIN;
    }

    /// DEFENSE: Assign user roles
    function assignRole(address user, Role role) external onlyAdmin {
        userRoles[user] = role;
        emit RoleAssigned(user, role);
    }

    /// DEFENSE: Define policy rule (e.g., "upgrade" needs ADMIN)
    function definePolicy(string calldata actionId, Role requiredRole) external onlyAdmin {
        actionPolicy[actionId] = requiredRole;
        emit PolicyDefined(actionId, requiredRole);
    }

    /// DEFENSE: Execute action with policy enforcement
    function executeAction(string calldata actionId) external {
        Role required = actionPolicy[actionId];
        Role actual = userRoles[msg.sender];

        if (actual < required) {
            emit AttackDetected(msg.sender, "Access Control Violation");
            revert("Access denied: insufficient role");
        }

        emit ActionExecuted(msg.sender, actionId);
    }

    /// ATTACK Simulation: User tries unassigned or admin-only action
    function attackBypass(string calldata actionId) external {
        emit AttackDetected(msg.sender, "Unauthorized attempt to bypass policy");
        revert("Simulated attack");
    }

    /// View audit
    function getPolicy(string calldata actionId) external view returns (Role) {
        return actionPolicy[actionId];
    }

    function getUserRole(address user) external view returns (Role) {
        return userRoles[user];
    }
}
