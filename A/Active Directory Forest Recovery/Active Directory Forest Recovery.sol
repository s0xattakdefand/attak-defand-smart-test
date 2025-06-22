// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Web3 Forest Recovery — Role Tree Snapshot & Restore

contract ADForestRecovery {
    address public admin;
    mapping(address => string) public roles;
    mapping(address => bool) public trustedBackups;

    event RoleAssigned(address indexed user, string role);
    event RoleRevoked(address indexed user);
    event ForestSnapshot(bytes32 indexed snapshotHash);
    event ForestRestored(address indexed by, bytes32 snapshotHash);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /// Assign or update role
    function setRole(address user, string calldata role) external onlyAdmin {
        roles[user] = role;
        emit RoleAssigned(user, role);
    }

    /// Revoke role
    function revokeRole(address user) external onlyAdmin {
        delete roles[user];
        emit RoleRevoked(user);
    }

    /// Record snapshot hash (off-chain backup)
    function snapshotForest(bytes32 hash) external onlyAdmin {
        emit ForestSnapshot(hash);
    }

    /// Trust a backup signer/address
    function approveBackup(address backup) external onlyAdmin {
        trustedBackups[backup] = true;
    }

    /// Restore from signed snapshot (off-chain verified)
    function restoreFromBackup(address[] calldata users, string[] calldata restoredRoles, bytes32 snapshotHash) external {
        require(trustedBackups[msg.sender], "Untrusted restore");
        require(users.length == restoredRoles.length, "Mismatched input");

        for (uint i = 0; i < users.length; i++) {
            roles[users[i]] = restoredRoles[i];
            emit RoleAssigned(users[i], restoredRoles[i]);
        }

        emit ForestRestored(msg.sender, snapshotHash);
    }

    function getRole(address user) external view returns (string memory) {
        return roles[user];
    }
}
