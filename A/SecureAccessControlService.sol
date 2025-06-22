// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SecureAccessControlService {
    address public owner;
    mapping(address => bool) private authorized;

    event AuthorizationUpdated(address indexed user, bool status);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function setAuthorized(address user, bool status) public onlyOwner {
        authorized[user] = status;
        emit AuthorizationUpdated(user, status);
    }

    function isAuthorized(address user) public view returns (bool) {
        return authorized[user];
    }
}
