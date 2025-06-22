// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Drift, Wildcard Injection, Hijack
/// Defense Types: Explicit ACE Map, Logs, Call-time Check

contract AccessControlEntryEngine {
    address public admin;

    struct ACE {
        bool allowed;
        uint256 expiresAt; // 0 = no expiration
    }

    // ACE: subject → action → ACE struct
    mapping(address => mapping(string => ACE)) public aceTable;

    event ACEGranted(address indexed subject, string action, uint256 expiresAt);
    event ACERevoked(address indexed subject, string action);
    event AccessUsed(address indexed subject, string action);
    event AttackDetected(address indexed attacker, string reason);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /// DEFENSE: Grant an ACE (e.g., Alice can `mint`)
    function grantACE(address subject, string calldata action, uint256 ttl) external onlyAdmin {
        aceTable[subject][action] = ACE(true, ttl == 0 ? 0 : block.timestamp + ttl);
        emit ACEGranted(subject, action, aceTable[subject][action].expiresAt);
    }

    /// DEFENSE: Revoke ACE
    function revokeACE(address subject, string calldata action) external onlyAdmin {
        delete aceTable[subject][action];
        emit ACERevoked(subject, action);
    }

    /// DEFENSE: Enforce access before executing
    function performAction(string calldata action) external {
        ACE memory entry = aceTable[msg.sender][action];
        if (
            !entry.allowed ||
            (entry.expiresAt != 0 && block.timestamp > entry.expiresAt)
        ) {
            emit AttackDetected(msg.sender, "Unauthorized ACE access attempt");
            revert("Access denied");
        }

        emit AccessUsed(msg.sender, action);
        // Business logic would go here
    }

    /// ATTACK: Simulate rogue caller using `mint` without ACE
    function attackUnauthorizedAccess(string calldata action) external {
        emit AttackDetected(msg.sender, "Simulated rogue ACE attempt");
        revert("Blocked fake ACE usage");
    }

    /// View current ACE
    function getACE(address user, string calldata action) external view returns (bool allowed, uint256 expiresAt) {
        ACE memory entry = aceTable[user][action];
        return (entry.allowed, entry.expiresAt);
    }
}
