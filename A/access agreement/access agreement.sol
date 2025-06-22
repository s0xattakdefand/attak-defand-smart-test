// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Unauthorized Access, Drifted Access, Overbroad Rights
/// Defense Types: Access Registry, Expiration, Event Logging

contract AccessManager {
    address public admin;

    struct AccessGrant {
        bool allowed;
        uint256 expiresAt; // 0 = no expiry
    }

    mapping(address => mapping(string => AccessGrant)) public userAccess;

    event AccessGranted(address indexed user, string action, uint256 expiresAt);
    event AccessRevoked(address indexed user, string action);
    event AccessUsed(address indexed user, string action);
    event AttackDetected(address indexed user, string reason);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /// DEFENSE: Grant access for a specific action
    function grantAccess(address user, string calldata action, uint256 ttl) external onlyAdmin {
        userAccess[user][action] = AccessGrant({
            allowed: true,
            expiresAt: ttl == 0 ? 0 : block.timestamp + ttl
        });

        emit AccessGranted(user, action, userAccess[user][action].expiresAt);
    }

    /// DEFENSE: Revoke access
    function revokeAccess(address user, string calldata action) external onlyAdmin {
        delete userAccess[user][action];
        emit AccessRevoked(user, action);
    }

    /// DEFENSE: Check and log usage
    function useAccess(string calldata action) external {
        AccessGrant memory grant = userAccess[msg.sender][action];
        if (!grant.allowed || (grant.expiresAt != 0 && block.timestamp > grant.expiresAt)) {
            emit AttackDetected(msg.sender, "Unauthorized or expired access attempt");
            revert("Access denied");
        }

        emit AccessUsed(msg.sender, action);
    }

    /// ATTACK Simulation: Try using access without being granted
    function attackAccess(string calldata action) external {
        emit AttackDetected(msg.sender, "Fake access simulation");
        revert("Blocked simulated attacker");
    }

    /// View access for audit/logging
    function viewAccess(address user, string calldata action) external view returns (bool active, uint256 expiresAt) {
        AccessGrant memory grant = userAccess[user][action];
        bool isActive = grant.allowed && (grant.expiresAt == 0 || block.timestamp <= grant.expiresAt);
        return (isActive, grant.expiresAt);
    }
}
