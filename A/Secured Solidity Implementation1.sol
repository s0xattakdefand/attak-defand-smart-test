// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SecureACL {
    mapping(address => bool) private adminACL;
    address public owner;

    event AdminSet(address indexed user, bool status);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyAdmin() {
        require(adminACL[msg.sender], "Not admin");
        _;
    }

    constructor() {
        owner = msg.sender;
        adminACL[msg.sender] = true; // owner is default admin
    }

    function setAdmin(address user, bool status) public onlyOwner {
        adminACL[user] = status;
        emit AdminSet(user, status);
    }

    function isAdmin(address user) public view returns (bool) {
        return adminACL[user];
    }

    function sensitiveAction() public onlyAdmin {
        // Critical admin function, safely restricted
    }
}
