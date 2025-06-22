// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Web3 Active Directory Services (ADS)
contract ActiveDirectoryServices {
    address public admin;

    enum Role { NONE, VIEWER, OPERATOR, ADMIN }

    struct Identity {
        string name;
        bool registered;
    }

    mapping(address => Identity) public identities;
    mapping(address => Role) public roles;
    mapping(string => mapping(address => bool)) public groupMembership;

    event IdentityRegistered(address indexed user, string name);
    event RoleGranted(address indexed user, Role role);
    event RoleRevoked(address indexed user);
    event AddedToGroup(address indexed user, string group);
    event RemovedFromGroup(address indexed user, string group);
    event AccessLogged(address indexed user, string action);
    event AccessDenied(address indexed user, string action);

    modifier onlyAdmin() {
        require(roles[msg.sender] == Role.ADMIN, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
        roles[admin] = Role.ADMIN;
    }

    // Identity functions
    function registerIdentity(string calldata name) external {
        identities[msg.sender] = Identity(name, true);
        emit IdentityRegistered(msg.sender, name);
    }

    // Role functions
    function grantRole(address user, Role role) external onlyAdmin {
        roles[user] = role;
        emit RoleGranted(user, role);
    }

    function revokeRole(address user) external onlyAdmin {
        delete roles[user];
        emit RoleRevoked(user);
    }

    // Group functions
    function joinGroup(string calldata group) external {
        groupMembership[group][msg.sender] = true;
        emit AddedToGroup(msg.sender, group);
    }

    function leaveGroup(string calldata group) external {
        delete groupMembership[group][msg.sender];
        emit RemovedFromGroup(msg.sender, group);
    }

    // Access logging
    function accessAction(string calldata action, Role requiredRole) external {
        if (roles[msg.sender] >= requiredRole) {
            emit AccessLogged(msg.sender, action);
        } else {
            emit AccessDenied(msg.sender, action);
            revert("Insufficient role");
        }
    }

    function isInGroup(address user, string calldata group) external view returns (bool) {
        return groupMembership[group][user];
    }

    function getRole(address user) external view returns (Role) {
        return roles[user];
    }

    function getIdentity(address user) external view returns (string memory name, bool registered) {
        Identity memory id = identities[user];
        return (id.name, id.registered);
    }
}
