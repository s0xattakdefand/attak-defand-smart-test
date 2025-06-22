// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AuditTrail - Tracks on-chain activity for accountability and forensic audit

contract AuditTrail {
    address public auditor;

    enum LogLevel { INFO, WARNING, CRITICAL }

    event ActionLogged(
        address indexed actor,
        LogLevel level,
        string category,
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

    function log(
        LogLevel level,
        string calldata category,
        string calldata message
    ) external {
        emit ActionLogged(msg.sender, level, category, message, msg.sig, block.timestamp);
    }

    function logAdmin(
        LogLevel level,
        string calldata category,
        string calldata message
    ) external onlyAuditor {
        emit ActionLogged(msg.sender, level, category, message, msg.sig, block.timestamp);
    }
}
