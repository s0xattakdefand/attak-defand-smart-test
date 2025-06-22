// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract MACEnforcer {
    mapping(address => uint8) private clearanceLevel;
    address public rootSystem;

    modifier hasClearance(uint8 required) {
        require(clearanceLevel[msg.sender] >= required, "Insufficient clearance");
        _;
    }

    constructor() {
        rootSystem = msg.sender;
        clearanceLevel[msg.sender] = 10; // Top secret
    }

    function assign(address user, uint8 level) external {
        require(msg.sender == rootSystem, "Only system can assign");
        clearanceLevel[user] = level;
    }

    function accessTopSecret() external hasClearance(5) returns (string memory) {
        return "Access granted to MAC protected data.";
    }

    function getMyClearance() external view returns (uint8) {
        return clearanceLevel[msg.sender];
    }
}
