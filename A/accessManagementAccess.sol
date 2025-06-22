// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PoorAccessManagement {
    address public owner;
    mapping(address => bool) public managers;

    constructor() {
        owner = msg.sender;
        managers[msg.sender] = true;
    }

    // Vulnerable: anyone can assign manager role
    function assignManager(address user) public {
        managers[user] = true;
    }

    modifier onlyManager() {
        require(managers[msg.sender], "Not a manager");
        _;
    }

    function sensitiveFunction() public onlyManager {
        // critical function
    }
}
