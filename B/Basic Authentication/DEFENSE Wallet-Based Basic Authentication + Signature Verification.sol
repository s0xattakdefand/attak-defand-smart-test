// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BasicAuthSecure {
    mapping(address => bool) public isAuthenticated;

    event Authenticated(address indexed user);

    function login() public {
        isAuthenticated[msg.sender] = true;
        emit Authenticated(msg.sender);
    }

    function isLoggedIn(address user) public view returns (bool) {
        return isAuthenticated[user];
    }

    function logout() public {
        isAuthenticated[msg.sender] = false;
    }
}
