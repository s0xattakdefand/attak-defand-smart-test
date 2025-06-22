// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AccessControlService {
    mapping(address => bool) public authorized;

    // Vulnerable: Anyone can modify authorization status
    function setAuthorized(address user, bool status) public {
        authorized[user] = status;
    }

    function isAuthorized(address user) public view returns (bool) {
        return authorized[user];
    }
}
