// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AdminBinding {
    mapping(address => bool) public isWhitelisted;
    address public admin;

    event Whitelisted(address indexed user);
    event Revoked(address indexed user);

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can perform this action");
        _;
    }

    function bindRole(address user) public onlyAdmin {
        isWhitelisted[user] = true;
        emit Whitelisted(user);
    }

    function revokeRole(address user) public onlyAdmin {
        isWhitelisted[user] = false;
        emit Revoked(user);
    }

    function checkWhitelisted(address user) public view returns (bool) {
        return isWhitelisted[user];
    }
}
