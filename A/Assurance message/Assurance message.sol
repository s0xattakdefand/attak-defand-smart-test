// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AssuranceMessageLog - Broadcasts signed assurance statements for smart contracts and protocols

contract AssuranceMessageLog {
    address public admin;

    enum Category { Security, ZKProof, Governance, Compliance, Simulation, Assumption }

    struct Message {
        bytes32 id;
        address source;
        Category category;
        string content;
        string reference; // IPFS hash or report URL
        uint256 timestamp;
    }

    mapping(bytes32 => Message) public messages;
    bytes32[] public messageIds;

    event AssuranceMessagePosted(bytes32 indexed id, address source, Category category, string content);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function postMessage(
        Category category,
        string calldata content,
        string calldata reference
    ) external onlyAdmin returns (bytes32 id) {
        id = keccak256(abi.encodePacked(category, content, block.timestamp));
        messages[id] = Message({
            id: id,
            source: msg.sender,
            category: category,
            content: content,
            reference: reference,
            timestamp: block.timestamp
        });
        messageIds.push(id);
        emit AssuranceMessagePosted(id, msg.sender, category, content);
        return id;
    }

    function getMessage(bytes32 id) external view returns (Message memory) {
        return messages[id];
    }

    function getAllMessageIds() external view returns (bytes32[] memory) {
        return messageIds;
    }
}
