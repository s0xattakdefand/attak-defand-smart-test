// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SecureBroadcastAddress {
    address public admin;
    mapping(address => bool) public broadcasters;

    event BroadcastToAll(string topic, string message, address indexed broadcaster);

    constructor() {
        admin = msg.sender;
        broadcasters[admin] = true;
    }

    modifier onlyBroadcaster() {
        require(broadcasters[msg.sender], "Unauthorized");
        _;
    }

    function addBroadcaster(address user) public {
        require(msg.sender == admin, "Admin only");
        broadcasters[user] = true;
    }

    function removeBroadcaster(address user) public {
        require(msg.sender == admin, "Admin only");
        broadcasters[user] = false;
    }

    function broadcast(string calldata topic, string calldata message) public onlyBroadcaster {
        emit BroadcastToAll(topic, message, msg.sender);
    }
}
