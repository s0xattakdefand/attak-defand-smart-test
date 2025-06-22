// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AuditTrail - Logs structured audit events for tamper-evident traceability

contract AuditTrail {
    address public owner;

    enum Severity { INFO, WARNING, CRITICAL }

    event TrailEntry(
        address indexed actor,
        Severity severity,
        string module,
        string message,
        bytes4 selector,
        uint256 timestamp
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function logInfo(string calldata module, string calldata message) external {
        emit TrailEntry(msg.sender, Severity.INFO, module, message, msg.sig, block.timestamp);
    }

    function logWarning(string calldata module, string calldata message) external {
        emit TrailEntry(msg.sender, Severity.WARNING, module, message, msg.sig, block.timestamp);
    }

    function logCritical(string calldata module, string calldata message) external onlyOwner {
        emit TrailEntry(msg.sender, Severity.CRITICAL, module, message, msg.sig, block.timestamp);
    }
}
