// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract WeakBasicAuth {
    address public user;

    // ❌ No validation — anyone can pretend to "login"
    function login(address _user) public {
        user = _user;
    }

    function isLoggedIn(address _check) public view returns (bool) {
        return _check == user;
    }
}
