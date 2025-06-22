// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IRoleUplink {
    function pushRoleMutation(string calldata label, address user, bytes32 role) external;
}

contract RBACGuard {
    mapping(address => mapping(bytes32 => bool)) public hasRole;
    mapping(bytes32 => bytes32) public adminOf;

    address public rootAdmin;
    IRoleUplink public uplink;

    event RoleGranted(address indexed user, bytes32 role);
    event RoleRevoked(address indexed user, bytes32 role);

    constructor(address _uplink) {
        rootAdmin = msg.sender;
        uplink = IRoleUplink(_uplink);
        hasRole[msg.sender][keccak256("SUPER_ADMIN")] = true;
    }

    modifier onlyRole(bytes32 role) {
        require(hasRole[msg.sender][role], "Access denied");
        _;
    }

    function grant(address user, bytes32 role) external onlyRole(adminOf[role]) {
        hasRole[user][role] = true;
        emit RoleGranted(user, role);
        uplink.pushRoleMutation("grant", user, role);
    }

    function revoke(address user, bytes32 role) external onlyRole(adminOf[role]) {
        hasRole[user][role] = false;
        emit RoleRevoked(user, role);
        uplink.pushRoleMutation("revoke", user, role);
    }

    function setAdmin(bytes32 role, bytes32 adminRole) external onlyRole(keccak256("SUPER_ADMIN")) {
        adminOf[role] = adminRole;
    }

    function has(address user, bytes32 role) external view returns (bool) {
        return hasRole[user][role];
    }
}
