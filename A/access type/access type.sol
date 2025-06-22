// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Access Type Confusion, Drift, Execution Escalation
/// Defense Types: Typed Enforcement, Registry, Revocation

contract AccessTypeControl {
    address public admin;

    enum AccessType { NONE, READ, WRITE, EXECUTE, DELETE }

    mapping(address => mapping(string => AccessType)) public userAccessType;

    event AccessGranted(address indexed user, string resource, AccessType accessType);
    event AccessRevoked(address indexed user, string resource);
    event AccessUsed(address indexed user, string resource, AccessType accessType);
    event AttackDetected(address indexed attacker, string reason);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /// DEFENSE: Assign access type to user for resource
    function grantAccess(address user, string calldata resource, AccessType accessType) external onlyAdmin {
        userAccessType[user][resource] = accessType;
        emit AccessGranted(user, resource, accessType);
    }

    /// DEFENSE: Revoke user access to a resource
    function revokeAccess(address user, string calldata resource) external onlyAdmin {
        delete userAccessType[user][resource];
        emit AccessRevoked(user, resource);
    }

    /// DEFENSE: Use READ access
    function readResource(string calldata resource) external {
        if (userAccessType[msg.sender][resource] < AccessType.READ) {
            emit AttackDetected(msg.sender, "Unauthorized READ attempt");
            revert("Access denied: READ");
        }
        emit AccessUsed(msg.sender, resource, AccessType.READ);
    }

    /// DEFENSE: Use WRITE access
    function writeResource(string calldata resource) external {
        if (userAccessType[msg.sender][resource] < AccessType.WRITE) {
            emit AttackDetected(msg.sender, "Unauthorized WRITE attempt");
            revert("Access denied: WRITE");
        }
        emit AccessUsed(msg.sender, resource, AccessType.WRITE);
    }

    /// DEFENSE: Use DELETE access
    function deleteResource(string calldata resource) external {
        if (userAccessType[msg.sender][resource] < AccessType.DELETE) {
            emit AttackDetected(msg.sender, "Unauthorized DELETE attempt");
            revert("Access denied: DELETE");
        }
        emit AccessUsed(msg.sender, resource, AccessType.DELETE);
    }

    /// ATTACK Simulation: Try EXECUTE without access
    function attackExecute(string calldata resource) external {
        if (userAccessType[msg.sender][resource] < AccessType.EXECUTE) {
            emit AttackDetected(msg.sender, "Execution access escalation attempt");
            revert("Blocked: EXECUTE");
        }
    }

    /// View current access type
    function getAccessType(address user, string calldata resource) external view returns (AccessType) {
        return userAccessType[user][resource];
    }
}
