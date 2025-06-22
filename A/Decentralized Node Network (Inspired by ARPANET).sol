// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ARPANETInspiredNetwork {
    mapping(address => bool) public nodes;
    mapping(address => string[]) public messages;
    address public admin;

    event NodeRegistered(address indexed node);
    event MessageSent(address indexed from, string message);

    constructor() {
        admin = msg.sender;
        nodes[msg.sender] = true;
        emit NodeRegistered(msg.sender);
    }

    modifier onlyNode() {
        require(nodes[msg.sender], "Not a registered node");
        _;
    }

    // Register a new node (decentralized approval can be added)
    function registerNode(address node) public {
        require(msg.sender == admin || nodes[msg.sender], "Unauthorized");
        nodes[node] = true;
        emit NodeRegistered(node);
    }

    // Send message to network (broadcasted concept)
    function sendMessage(string calldata message) public onlyNode {
        messages[msg.sender].push(message);
        emit MessageSent(msg.sender, message);
    }

    function getMessageByIndex(address node, uint256 index) public view returns (string memory) {
        return messages[node][index];
    }

    function isNode(address node) public view returns (bool) {
        return nodes[node];
    }
}
