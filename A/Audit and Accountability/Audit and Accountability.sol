// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AuditLogger - Logs critical actions for on-chain audit and accountability

contract AuditLogger {
    address public admin;

    event ActionLogged(
        address indexed actor,
        string role,
        string action,
        string context,
        bytes4 selector,
        uint256 timestamp
    );

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /// @notice Logs any critical action
    function logAction(
        address actor,
        string calldata role,
        string calldata action,
        string calldata context
    ) external {
        emit ActionLogged(actor, role, action, context, msg.sig, block.timestamp);
    }

    /// @notice Log directly from contract using admin
    function logAdminAction(string calldata action, string calldata context) external onlyAdmin {
        emit ActionLogged(msg.sender, "Admin", action, context, msg.sig, block.timestamp);
    }
}
