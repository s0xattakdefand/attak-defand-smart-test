// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title ClassifiedDataRepository
 * @notice Stores data records with classification levels, enforces user clearances,
 *         and logs all administrative and access events.
 * Sources:
 *   • “Classification reflecting the highest classification being processed in an information system.
 *      Default classification is included in the caution statement affixed to an object.”
 *     CNSSI 4009-2015
 */
contract ClassifiedDataRepository {
    // Classification levels in ascending order of sensitivity
    enum Classification { Unclassified, Confidential, Secret, TopSecret, SystemHigh }

    address public owner;
    Classification public systemClassification;

    struct Record {
        string   value;
        Classification class;
        address  author;
        uint256  timestamp;
    }

    // user → their clearance level
    mapping(address => Classification) public clearance;
    // data key → record
    mapping(string => Record) private records;

    // Events
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event SystemClassificationSet(Classification indexed newClassification);
    event ClearanceAssigned(address indexed user, Classification indexed level);
    event RecordWritten(string indexed key, Classification indexed class, address indexed author);
    event RecordRead(string indexed key, Classification indexed class, address indexed reader);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier hasClearance(Classification required) {
        require(clearance[msg.sender] >= required, "Insufficient clearance");
        _;
    }

    constructor(Classification initialSystemClass) {
        owner = msg.sender;
        systemClassification = initialSystemClass;
        emit OwnershipTransferred(address(0), msg.sender);
        emit SystemClassificationSet(initialSystemClass);
    }

    /// @notice Transfer contract ownership
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    /// @notice Update the highest classification the system processes
    function setSystemClassification(Classification newClass) external onlyOwner {
        systemClassification = newClass;
        emit SystemClassificationSet(newClass);
    }

    /// @notice Assign a clearance level to a user
    function assignClearance(address user, Classification level) external onlyOwner {
        clearance[user] = level;
        emit ClearanceAssigned(user, level);
    }

    /// @notice Write or update a data record under a key
    /// @param key        Unique identifier for the record
    /// @param value      The data to store
    /// @param class      Classification level for this record
    function writeRecord(
        string calldata key,
        string calldata value,
        Classification class
    )
        external
        hasClearance(class)
    {
        require(class <= systemClassification, "Record above system classification");
        records[key] = Record({
            value:     value,
            class:     class,
            author:    msg.sender,
            timestamp: block.timestamp
        });
        emit RecordWritten(key, class, msg.sender);
    }

    /// @notice Read a data record (logs access)
    /// @param key  Identifier of the record to read
    /// @return value      The stored data
    /// @return class      The record’s classification
    /// @return author     The address that wrote the record
    /// @return timestamp  When the record was last written
    function readRecord(string calldata key)
        external
        hasClearance(records[key].class)
        returns (
            string memory value,
            Classification class,
            address author,
            uint256 timestamp
        )
    {
        Record storage r = records[key];
        require(bytes(r.value).length != 0, "Record does not exist");
        emit RecordRead(key, r.class, msg.sender);
        return (r.value, r.class, r.author, r.timestamp);
    }

    /// @notice View metadata for a record without logging
    function getRecordMeta(string calldata key)
        external
        view
        hasClearance(records[key].class)
        returns (
            Classification class,
            address author,
            uint256 timestamp
        )
    {
        Record storage r = records[key];
        require(bytes(r.value).length != 0, "Record does not exist");
        return (r.class, r.author, r.timestamp);
    }
}
