// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract OneWayOnly {
    mapping(address => string) public inbox;

    function sendMessage(string calldata msg_) external {
        inbox[msg.sender] = msg_; // No receiver acknowledgment
    }
}
