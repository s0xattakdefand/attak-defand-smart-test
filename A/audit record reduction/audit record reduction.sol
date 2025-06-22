// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AuditRecordReducer - Reduces audit records via Merkle root or hash commitment

contract AuditRecordReducer {
    address public owner;

    struct AuditBatch {
        bytes32 merkleRoot;
        string category;
        string uri; // optional off-chain storage reference (IPFS/Arweave)
        uint256 timestamp;
    }

    mapping(uint256 => AuditBatch) public batches;
    uint256 public batchCounter;

    event AuditBatchCommitted(
        uint256 indexed batchId,
        bytes32 indexed merkleRoot,
        string category,
        string uri,
        uint256 timestamp
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function commitAuditBatch(bytes32 merkleRoot, string calldata category, string calldata uri) external onlyOwner {
        uint256 batchId = batchCounter++;
        batches[batchId] = AuditBatch(merkleRoot, category, uri, block.timestamp);
        emit AuditBatchCommitted(batchId, merkleRoot, category, uri, block.timestamp);
    }

    function getBatch(uint256 batchId) external view returns (AuditBatch memory) {
        return batches[batchId];
    }
}
