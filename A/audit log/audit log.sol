// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AuditLog - Structured, indexed, and secure audit logging for Web3 systems

contract AuditLog {
    address public owner;

    enum Severity { INFO, WARNING, CRITICAL }

    event LogEntry(
        address indexed actor,
        Severity level,
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
        emit LogEntry(msg.sender, Severity.INFO, module, message, msg.sig, block.timestamp);
    }

    function logWarning(string calldata module, string calldata message) external {
        emit LogEntry(msg.sender, Severity.WARNING, module, message, msg.sig, block.timestamp);
    }

    function logCritical(string calldata module, string calldata message) external onlyOwner {
        emit LogEntry(msg.sender, Severity.CRITICAL, module, message, msg.sig, block.timestamp);
    }
}
