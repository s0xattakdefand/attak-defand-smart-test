// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title DataLifecycleAttackDefense - Full Attack and Defense Simulation for Data Lifecycle Vulnerabilities
/// @author ChatGPT

/// @notice Secure contract managing data lifecycle safely
contract SecureDataLifecycle {
    address public owner;

    struct Record {
        string data;
        uint256 createdAt;
        uint256 expiresAt;
        bool isActive;
    }

    mapping(uint256 => Record) public records;
    uint256 public recordCounter;

    event RecordCreated(uint256 indexed id, string data);
    event RecordArchived(uint256 indexed id);
    event RecordDeleted(uint256 indexed id);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function createRecord(string memory _data, uint256 _lifetimeSeconds) external onlyOwner returns (uint256) {
        recordCounter++;
        records[recordCounter] = Record({
            data: _data,
            createdAt: block.timestamp,
            expiresAt: block.timestamp + _lifetimeSeconds,
            isActive: true
        });

        emit RecordCreated(recordCounter, _data);
        return recordCounter;
    }

    function archiveExpiredRecord(uint256 _id) external onlyOwner {
        require(records[_id].isActive, "Already inactive");
        require(block.timestamp >= records[_id].expiresAt, "Not expired yet");

        records[_id].isActive = false;
        emit RecordArchived(_id);
    }

    function deleteRecord(uint256 _id) external onlyOwner {
        require(!records[_id].isActive, "Must archive first");
        delete records[_id];
        emit RecordDeleted(_id);
    }

    function readRecord(uint256 _id) external view returns (string memory) {
        require(records[_id].isActive, "Inactive record");
        require(block.timestamp < records[_id].expiresAt, "Record expired");
        return records[_id].data;
    }
}

/// @notice Attack contract trying to resurrect or misuse expired/dead data
contract DataLifecycleIntruder {
    address public target;

    constructor(address _target) {
        target = _target;
    }

    function resurrectRecord(uint256 _id) external returns (bool success) {
        // Try to access expired or archived record
        (success, ) = target.call(
            abi.encodeWithSignature("readRecord(uint256)", _id)
        );
        // Success is FALSE if defense is working properly
    }
}
