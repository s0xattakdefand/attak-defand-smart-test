// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AuditRecordStore - Emits structured, verifiable audit records

contract AuditRecordStore {
    address public auditor;

    enum RecordType { TRANSACTION, ACCESS, COMPLIANCE, ZKPROOF, OFFCHAIN }

    event AuditRecord(
        address indexed actor,
        RecordType recordType,
        string module,
        string message,
        bytes4 selector,
        uint256 timestamp
    );

    modifier onlyAuditor() {
        require(msg.sender == auditor, "Not authorized");
        _;
    }

    constructor() {
        auditor = msg.sender;
    }

    function createRecord(
        RecordType recordType,
        string calldata module,
        string calldata message
    ) external {
        emit AuditRecord(msg.sender, recordType, module, message, msg.sig, block.timestamp);
    }

    function createAdminRecord(
        RecordType recordType,
        string calldata module,
        string calldata message
    ) external onlyAuditor {
        emit AuditRecord(msg.sender, recordType, module, message, msg.sig, block.timestamp);
    }
}
