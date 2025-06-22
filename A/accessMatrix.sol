// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PoorAccessMatrix {
    mapping(address => mapping(bytes32 => bool)) public permissions;

    constructor() {
        permissions[msg.sender]["ADMIN"] = true;
    }

    // Vulnerable: Any user can grant themselves permissions
    function grantPermission(address user, bytes32 permission) public {
        permissions[user][permission] = true;
    }

    modifier hasPermission(bytes32 permission) {
        require(permissions[msg.sender][permission], "Access denied");
        _;
    }

    function criticalAdminFunction() public hasPermission("ADMIN") {
        // sensitive admin functionality
    }
}
