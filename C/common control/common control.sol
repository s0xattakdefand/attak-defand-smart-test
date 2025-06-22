// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CommonControlRegistry {
    address public admin;

    mapping(address => mapping(bytes32 => bool)) public roles;      // roles[user][role] = true/false
    mapping(bytes32 => bool) public globalFlags;                    // globalFlags["PAUSED"] = true
    mapping(bytes32 => address) public controlOwners;               // owner of control key (optional)

    event RoleGranted(address indexed user, bytes32 indexed role);
    event RoleRevoked(address indexed user, bytes32 indexed role);
    event FlagSet(bytes32 indexed key, bool value);
    event ControlOwnerSet(bytes32 indexed key, address indexed owner);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier onlyControlOwner(bytes32 key) {
        require(msg.sender == controlOwners[key], "Not control owner");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function grantRole(address user, bytes32 role) external onlyAdmin {
        roles[user][role] = true;
        emit RoleGranted(user, role);
    }

    function revokeRole(address user, bytes32 role) external onlyAdmin {
        roles[user][role] = false;
        emit RoleRevoked(user, role);
    }

    function hasRole(address user, bytes32 role) external view returns (bool) {
        return roles[user][role];
    }

    function setFlag(bytes32 key, bool value) external onlyAdmin {
        globalFlags[key] = value;
        emit FlagSet(key, value);
    }

    function getFlag(bytes32 key) external view returns (bool) {
        return globalFlags[key];
    }

    function setControlOwner(bytes32 key, address owner) external onlyAdmin {
        controlOwners[key] = owner;
        emit ControlOwnerSet(key, owner);
    }

    function setFlagAsOwner(bytes32 key, bool value) external onlyControlOwner(key) {
        globalFlags[key] = value;
        emit FlagSet(key, value);
    }
}
