// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title GeneralRecordScheduleAttackDefense - Full Attack and Defense Simulation for GRS in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Record Management (Vulnerable to Tampering and Retention Failures)
contract InsecureGRS {
    struct Record {
        string data;
        uint256 timestamp;
    }

    mapping(uint256 => Record) public records;
    uint256 public recordCounter;

    event RecordAdded(uint256 indexed id, string data);
    event RecordUpdated(uint256 indexed id, string newData);
    event RecordDeleted(uint256 indexed id);

    function addRecord(string memory data) external {
        recordCounter++;
        records[recordCounter] = Record(data, block.timestamp);
        emit RecordAdded(recordCounter, data);
    }

    function updateRecord(uint256 id, string memory newData) external {
        // BAD: Anyone can update records without restriction
        records[id].data = newData;
        emit RecordUpdated(id, newData);
    }

    function deleteRecord(uint256 id) external {
        // BAD: Anyone can delete records anytime
        delete records[id];
        emit RecordDeleted(id);
    }
}

/// @notice Secure Record Management (Controlled, Auditable, and Timed Deletion)
contract SecureGRS {
    address public immutable owner;
    uint256 public retentionPeriod; // e.g., 30 days

    struct Record {
        bytes32 dataHash;
        uint256 createdAt;
        bool deleted;
    }

    mapping(uint256 => Record) public records;
    uint256 public recordCounter;

    event RecordCommitted(uint256 indexed id, bytes32 dataHash, uint256 createdAt);
    event RecordScheduledForDeletion(uint256 indexed id, uint256 createdAt);
    event RecordDeleted(uint256 indexed id, uint256 deletedAt);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    constructor(uint256 _retentionPeriod) {
        owner = msg.sender;
        retentionPeriod = _retentionPeriod;
    }

    function addRecord(bytes32 dataHash) external onlyOwner {
        recordCounter++;
        records[recordCounter] = Record(dataHash, block.timestamp, false);
        emit RecordCommitted(recordCounter, dataHash, block.timestamp);
    }

    function scheduleDeletion(uint256 id) external onlyOwner {
        Record storage rec = records[id];
        require(!rec.deleted, "Already deleted");
        require(block.timestamp >= rec.createdAt + retentionPeriod, "Retention period not passed");

        rec.deleted = true;
        emit RecordDeleted(id, block.timestamp);
    }

    function getRecord(uint256 id) external view returns (bytes32, uint256, bool) {
        Record memory rec = records[id];
        return (rec.dataHash, rec.createdAt, rec.deleted);
    }
}

/// @notice Attack contract simulating unauthorized record tampering
contract GRSIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function tamperRecord(uint256 id, string memory fakeData) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("updateRecord(uint256,string)", id, fakeData)
        );
    }
}
