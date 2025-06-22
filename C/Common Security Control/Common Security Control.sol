// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CommonSecurityControl {
    address public admin;

    mapping(bytes32 => mapping(address => bool)) public roles;
    bool public globallyPaused;

    event RoleGranted(bytes32 indexed role, address indexed user);
    event RoleRevoked(bytes32 indexed role, address indexed user);
    event GlobalPauseToggled(bool paused);

    modifier onlyAdmin() {
        require(msg.sender == admin, "CSC: Not admin");
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

    function setGlobalPause(bool pauseStatus) external onlyAdmin {
        globallyPaused = pauseStatus;
        emit GlobalPauseToggled(pauseStatus);
    }

    function isPaused() external view returns (bool) {
        return globallyPaused;
    }
}
