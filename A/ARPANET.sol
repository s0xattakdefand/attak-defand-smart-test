// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Mimics centralized ARPANET-like node
contract CentralizedNode {
    address public controller;

    constructor() {
        controller = msg.sender;
    }

    function sendMessage(string calldata message) public view returns (string memory) {
        require(msg.sender == controller, "Only central node can message");
        return message;
    }
}
