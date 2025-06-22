// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract OctetMaskAccess {
    uint8 constant ADMIN_MASK = 0xF0; // upper 4 bits
    uint8 constant USER_MASK =  0x0F; // lower 4 bits

    mapping(address => uint8) public accessLevel;

    function setAccess(address user, uint8 octet) external {
        require(octet <= 0xFF, "Invalid octet"); // 1 octet = max 255
        accessLevel[user] = octet;
    }

    function isAdmin(address user) public view returns (bool) {
        return (accessLevel[user] & ADMIN_MASK) > 0;
    }

    function isUser(address user) public view returns (bool) {
        return (accessLevel[user] & USER_MASK) > 0;
    }
}
