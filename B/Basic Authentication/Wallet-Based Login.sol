// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract WalletBasedLogin {
    mapping(address => bool) public isUser;

    event UserLoggedIn(address indexed user);
    event UserLoggedOut(address indexed user);

    // Users authenticate themselves using msg.sender
    function login() public {
        isUser[msg.sender] = true;
        emit UserLoggedIn(msg.sender);
    }

    function logout() public {
        isUser[msg.sender] = false;
        emit UserLoggedOut(msg.sender);
    }

    function isLoggedIn(address user) public view returns (bool) {
        return isUser[user];
    }
}
