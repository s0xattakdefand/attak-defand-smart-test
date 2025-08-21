// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Doubly Linked List smart contract
contract DoublyLinkedList {
    // Struct to represent a node in the doubly linked list
    struct Node {
        uint256 id;           // Unique identifier for the node
        bytes32 data;         // Data stored in the node
        uint256 prev;         // ID of the previous node
        uint256 next;         // ID of the next node
    }

    // Mapping to store nodes by their ID
    mapping(uint256 => Node) public nodes;

    // Head and tail of the list
    uint256 public head;
    uint256 public tail;
    uint256 public nodeCount;

    // Owner of the contract
    address public owner;

    // Event emitted when a node is added
    event NodeAdded(uint256 indexed id, bytes32 data, uint256 prev, uint256 next);

    // Event emitted when a node is removed
    event NodeRemoved(uint256 indexed id);

    // Modifier to restrict actions to the owner
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    // Constructor to initialize the owner
    constructor() {
        owner = msg.sender;
        head = 0;
        tail = 0;
        nodeCount = 0;
    }

    // Add a new node with data to the end of the list
    function addNode(bytes32 data) external onlyOwner returns (uint256) {
        nodeCount++;
        uint256 newNodeId = nodeCount;

        nodes[newNodeId] = Node({
            id: newNodeId,
            data: data,
            prev: tail,
            next: 0
        });

        if (head == 0) {
            // First node
            head = newNodeId;
            tail = newNodeId;
        } else {
            // Update the current tail's next pointer
            nodes[tail].next = newNodeId;
            // Update tail to the new node
            tail = newNodeId;
        }

        emit NodeAdded(newNodeId, data, nodes[newNodeId].prev, nodes[newNodeId].next);
        return newNodeId;
    }

    // Remove a node by its ID
    function removeNode(uint256 id) external onlyOwner {
        require(id > 0 && id <= nodeCount, "Invalid node ID");
        require(nodes[id].id != 0, "Node does not exist");

        Node memory node = nodes[id];

        // Update the previous node's next pointer
        if (node.prev != 0) {
            nodes[node.prev].next = node.next;
        } else {
            // Node is head
            head = node.next;
        }

        // Update the next node's prev pointer
        if (node.next != 0) {
            nodes[node.next].prev = node.prev;
        } else {
            // Node is tail
            tail = node.prev;
        }

        // Delete the node
        delete nodes[id];
        emit NodeRemoved(id);
    }

    // Get node details by ID
    function getNode(uint256 id) external view returns (uint256, bytes32, uint256, uint256) {
        require(id > 0 && id <= nodeCount, "Invalid node ID");
        require(nodes[id].id != 0, "Node does not exist");
        Node memory node = nodes[id];
        return (node.id, node.data, node.prev, node.next);
    }

    // Get all node IDs in order (from head to tail)
    function getAllNodes() external view returns (uint256[] memory) {
        uint256[] memory nodeIds = new uint256[](nodeCount);
        uint256 current = head;
        uint256 index = 0;

        while (current != 0 && index < nodeCount) {
            nodeIds[index] = current;
            current = nodes[current].next;
            index++;
        }

        // Return only the filled portion of the array
        uint256[] memory result = new uint256[](index);
        for (uint256 i = 0; i < index; i++) {
            result[i] = nodeIds[i];
        }
        return result;
    }

    // Get the list size
    function getListSize() external view returns (uint256) {
        return nodeCount;
    }

    // Prevent accidental ETH deposits
    receive() external payable {
        revert("Contract does not accept ETH");
    }
}