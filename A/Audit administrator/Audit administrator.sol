// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AuditAdminManager - Manages auditor roles and enforces secure logging

contract AuditAdminManager {
    address public owner;

    mapping(address => bool) public auditAdmins;

    event AuditLog(address indexed admin, string action, string context, bytes4 selector, uint256 timestamp);
    event AuditAdminUpdated(address indexed admin, bool isAuthorized);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyAuditAdmin() {
        require(auditAdmins[msg.sender], "Not audit admin");
        _;
    }

    constructor() {
        owner = msg.sender;
        auditAdmins[msg.sender] = true;
        emit AuditAdminUpdated(msg.sender, true);
    }

    function setAuditAdmin(address admin, bool authorized) external onlyOwner {
        auditAdmins[admin] = authorized;
        emit AuditAdminUpdated(admin, authorized);
    }

    function logAction(string calldata action, string calldata context) external onlyAuditAdmin {
        emit AuditLog(msg.sender, action, context, msg.sig, block.timestamp);
    }

    function isAuditAdmin(address account) external view returns (bool) {
        return auditAdmins[account];
    }
}
