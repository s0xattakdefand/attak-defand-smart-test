// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// EventAggregator — Logs and hashes smart contract events for zk/offchain validation
contract EventAggregator {
    address public admin;

    bytes32[] public eventHashes;
    bytes32 public finalRoot;

    event AggregatedEvent(bytes32 indexed eventHash, string category, string payload);
    event AggregationFinalized(bytes32 root);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function logEvent(string calldata category, string calldata payload) external onlyAdmin {
        bytes32 hash = keccak256(abi.encodePacked(category, payload, block.timestamp, msg.sender));
        eventHashes.push(hash);
        emit AggregatedEvent(hash, category, payload);
    }

    function finalizeAggregation() external onlyAdmin returns (bytes32 root) {
        root = keccak256(abi.encodePacked(eventHashes));
        finalRoot = root;
        emit AggregationFinalized(root);
    }

    function getAllEventHashes() external view returns (bytes32[] memory) {
        return eventHashes;
    }

    function getRoot() external view returns (bytes32) {
        return finalRoot;
    }
}
