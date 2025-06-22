// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PoorACL {
    mapping(address => bool) public adminACL;
    address public owner;

    constructor() {
        owner = msg.sender;
        adminACL[msg.sender] = true;
    }

    modifier onlyAdmin() {
        require(adminACL[msg.sender], "Not admin");
        _;
    }

    function setAdmin(address user, bool status) public {
        adminACL[user] = status; // Vulnerable: Anyone can modify ACL!
    }

    function sensitiveAction() public onlyAdmin {
        // Critical admin function
    }
}
