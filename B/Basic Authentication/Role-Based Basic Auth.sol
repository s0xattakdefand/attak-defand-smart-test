// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RoleBasedBasicAuth {
    mapping(address => bool) public isAdmin;

    event AdminLoggedIn(address indexed user);
    event AdminAdded(address indexed newAdmin);

    address public owner;

    constructor() {
        owner = msg.sender;
        isAdmin[msg.sender] = true; // contract deployer is the first admin
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not the owner");
        _;
    }

    modifier onlyAdmin() {
        require(isAdmin[msg.sender], "Not an admin");
        _;
    }

    function loginAsAdmin() public view onlyAdmin returns (string memory) {
        return "You are authenticated as admin!";
    }

    function addAdmin(address newAdmin) public onlyOwner {
        isAdmin[newAdmin] = true;
        emit AdminAdded(newAdmin);
    }
}
