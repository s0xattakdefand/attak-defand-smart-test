// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SecureAccessManagement {
    address public owner;
    mapping(address => bool) private managers;

    event ManagerAssigned(address indexed user);
    event ManagerRevoked(address indexed user);

    constructor() {
        owner = msg.sender;
        managers[msg.sender] = true;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyManager() {
        require(managers[msg.sender], "Not manager");
        _;
    }

    // Securely assign manager roles
    function assignManager(address user) public onlyOwner {
        managers[user] = true;
        emit ManagerAssigned(user);
    }

    // Securely revoke manager roles
    function revokeManager(address user) public onlyOwner {
        managers[user] = false;
        emit ManagerRevoked(user);
    }

    // Public view function to check manager status
    function isManager(address user) public view returns (bool) {
        return managers[user];
    }

    // Critical function restricted to managers only
    function sensitiveFunction() public onlyManager {
        // Secure critical operation
    }
}
