// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SecureAccessMatrix {
    address public owner;
    
    // Access matrix (user => permission => granted)
    mapping(address => mapping(bytes32 => bool)) private permissions;

    event PermissionGranted(address indexed user, bytes32 permission);
    event PermissionRevoked(address indexed user, bytes32 permission);

    constructor() {
        owner = msg.sender;
        permissions[msg.sender]["ADMIN"] = true;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier hasPermission(bytes32 permission) {
        require(permissions[msg.sender][permission], "Access denied");
        _;
    }

    function grantPermission(address user, bytes32 permission) public onlyOwner {
        permissions[user][permission] = true;
        emit PermissionGranted(user, permission);
    }

    function revokePermission(address user, bytes32 permission) public onlyOwner {
        permissions[user][permission] = false;
        emit PermissionRevoked(user, permission);
    }

    function checkPermission(address user, bytes32 permission) public view returns (bool) {
        return permissions[user][permission];
    }

    function criticalAdminFunction() public hasPermission("ADMIN") {
        // safely restricted admin functionality
    }

    function regularUserFunction() public hasPermission("USER") {
        // functionality available to regular users
    }
}
