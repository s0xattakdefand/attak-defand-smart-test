// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DuplexMessenger {
    struct Message {
        string data;
        bool acknowledged;
    }

    mapping(address => mapping(address => Message)) public messages;

    function sendMessage(address to, string calldata data) external {
        messages[msg.sender][to] = Message(data, false);
    }

    function acknowledge(address sender) external {
        require(!messages[sender][msg.sender].acknowledged, "Already ACK'd");
        messages[sender][msg.sender].acknowledged = true;
    }

    function getStatus(address peer) external view returns (Message memory) {
        return messages[peer][msg.sender];
    }
}
