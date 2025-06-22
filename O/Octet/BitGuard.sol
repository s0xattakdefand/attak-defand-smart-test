// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract BitGuard {
    mapping(address => uint8) public permissionOctet;

    modifier onlyPermitted(uint8 requiredBits) {
        require((permissionOctet[msg.sender] & requiredBits) == requiredBits, "BitGuard: Access denied");
        _;
    }

    function setPermission(address user, uint8 bits) external {
        permissionOctet[user] = bits;
    }

    function hasPermission(address user, uint8 bits) external view returns (bool) {
        return (permissionOctet[user] & bits) == bits;
    }

    function privilegedAction() external onlyPermitted(0xF0) {
        // 0xF0 = Admin slot
    }

    function userAction() external onlyPermitted(0x0F) {
        // 0x0F = User slot
    }
}
