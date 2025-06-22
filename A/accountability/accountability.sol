// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Anonymous Action, Role Spoofing, Non-Repudiation Failure
/// Defense Types: Onchain Attribution, Role Audit, Action Flagging

contract AccountabilitySystem {
    address public rootAdmin;

    enum Role { NONE, USER, OPERATOR, ADMIN }

    mapping(address => Role) public roles;
    mapping(address => uint256) public infractions;

    event ActionTaken(address indexed user, Role role, string actionId);
    event MisbehaviorFlagged(address indexed user, string reason);
    event RoleAssigned(address indexed user, Role role);

    modifier onlyAdmin() {
        require(roles[msg.sender] == Role.ADMIN, "Admin only");
        _;
    }

    constructor() {
        rootAdmin = msg.sender;
        roles[msg.sender] = Role.ADMIN;
        emit RoleAssigned(msg.sender, Role.ADMIN);
    }

    /// DEFENSE: Admin assigns roles with audit
    function assignRole(address user, Role role) external onlyAdmin {
        roles[user] = role;
        emit RoleAssigned(user, role);
    }

    /// DEFENSE: Action with accountability trail
    function performAction(string calldata actionId) external {
        Role userRole = roles[msg.sender];
        if (userRole == Role.NONE) {
            _flagMisbehavior(msg.sender, "Unassigned role attempted action");
            revert("No role assigned");
        }

        emit ActionTaken(msg.sender, userRole, actionId);
    }

    /// ATTACK Simulation: Anonymous address attempts action
    function attackNoRoleAction() external {
        if (roles[msg.sender] == Role.NONE) {
            _flagMisbehavior(msg.sender, "Attack: no role");
            revert("Unauthorized");
        }
    }

    /// DEFENSE: Misbehavior flagging (internal)
    function _flagMisbehavior(address user, string memory reason) internal {
        infractions[user]++;
        emit MisbehaviorFlagged(user, reason);
    }

    /// View infraction count
    function getInfractions(address user) external view returns (uint256) {
        return infractions[user];
    }

    /// View current role
    function getRole(address user) external view returns (Role) {
        return roles[user];
    }
}
