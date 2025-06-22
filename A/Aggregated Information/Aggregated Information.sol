// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AggregatedInfoRegistry — Registry for offchain or zk-verified summaries
contract AggregatedInfoRegistry {
    address public admin;

    struct Aggregate {
        string topic;            // e.g., "DAO_VOTE", "ETH_PRICE", "ZK_BATCH"
        bytes32 dataHash;        // Hash or Merkle root of full dataset
        uint256 timestamp;
        string referenceURI;     // Optional IPFS or blob pointer
    }

    Aggregate[] public aggregates;

    event AggregatedInfoSubmitted(uint256 indexed id, string topic, bytes32 dataHash);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Admin only");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function submitAggregate(string calldata topic, bytes32 dataHash, string calldata referenceURI) external onlyAdmin returns (uint256) {
        aggregates.push(Aggregate(topic, dataHash, block.timestamp, referenceURI));
        uint256 id = aggregates.length - 1;
        emit AggregatedInfoSubmitted(id, topic, dataHash);
        return id;
    }

    function getAggregate(uint256 id) external view returns (Aggregate memory) {
        return aggregates[id];
    }

    function totalAggregates() external view returns (uint256) {
        return aggregates.length;
    }
}
