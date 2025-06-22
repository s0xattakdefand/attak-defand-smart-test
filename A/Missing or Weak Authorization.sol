// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract NoAuthorization {
    address public admin;
    uint256 public value;

    constructor() {
        admin = msg.sender;
    }

    // ❌ Anyone can update critical state!
    function setValue(uint256 newValue) public {
        value = newValue;
    }
}
