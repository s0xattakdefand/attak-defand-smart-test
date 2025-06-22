// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CommonControlProvider {
    address public admin;

    // Roles: keccak256("GOVERNOR"), etc.
    mapping(bytes32 => mapping(address => bool)) public roles;

    // Global control flags
    mapping(bytes32 => bool) public globalFlags;

    event RoleGranted(bytes32 indexed role, address indexed user);
    event RoleRevoked(bytes32 indexed role, address indexed user);
    event FlagSet(bytes32 indexed flag, bool value);

    modifier onlyAdmin() {
        require(msg.sender == admin, "CCP: Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function grantRole(bytes32 role, address user) external onlyAdmin {
        roles[role][user] = true;
        emit RoleGranted(role, user);
    }

    function revokeRole(bytes32 role, address user) external onlyAdmin {
        roles[role][user] = false;
        emit RoleRevoked(role, user);
    }

    function hasRole(bytes32 role, address user) external view returns (bool) {
        return roles[role][user];
    }

    function setFlag(bytes32 flag, bool value) external onlyAdmin {
        globalFlags[flag] = value;
        emit FlagSet(flag, value);
    }

    function isFlagEnabled(bytes32 flag) external view returns (bool) {
        return globalFlags[flag];
    }
}
