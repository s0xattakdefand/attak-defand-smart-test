// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BitFlagsVulnerable {
    mapping(address => uint8) public flags;

    uint8 constant IS_ADMIN = 0x01;
    uint8 constant CAN_MINT = 0x02;

    // ❌ Vulnerable: no check, user can call this directly
    function mint() public {
        // No permission check — anyone can mint
    }
}
