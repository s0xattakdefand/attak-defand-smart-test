// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Role Abuse, Unlogged Threats, Policy Drift
/// Defense Types: Role Guard, Classification Logging, Revocation

contract AppliedCybersecurityDivision {
    address public admin;

    enum Role { NONE, AUDITOR, RESPONDER, LEAD }
    enum Severity { LOW, MEDIUM, HIGH, CRITICAL }

    struct Threat {
        string summary;
        Severity severity;
        address reporter;
        uint256 timestamp;
    }

    mapping(address => Role) public roles;
    mapping(bytes32 => Threat) public threatLog;

    event RoleAssigned(address indexed user, Role role);
    event ThreatLogged(bytes32 indexed threatId, string summary, Severity severity, address reporter);
    event AttackDetected(address indexed user, string reason);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Admin only");
        _;
    }

    modifier onlyRole(Role required) {
        require(roles[msg.sender] == required, "Not authorized role");
        _;
    }

    constructor() {
        admin = msg.sender;
        roles[msg.sender] = Role.LEAD;
    }

    /// DEFENSE: Assign role to a security team member
    function assignRole(address user, Role role) external onlyAdmin {
        roles[user] = role;
        emit RoleAssigned(user, role);
    }

    /// DEFENSE: Log a security incident (AUDITOR-only)
    function logThreat(string calldata summary, Severity severity) external onlyRole(Role.AUDITOR) {
        bytes32 id = keccak256(abi.encodePacked(summary, msg.sender, block.timestamp));
        threatLog[id] = Threat(summary, severity, msg.sender, block.timestamp);
        emit ThreatLogged(id, summary, severity, msg.sender);
    }

    /// ATTACK SIMULATION: Log threat without proper role
    function attackLogThreat(string calldata summary) external {
        if (roles[msg.sender] != Role.AUDITOR) {
            emit AttackDetected(msg.sender, "Unauthorized threat logging attempt");
            revert("Access denied");
        }
    }

    /// VIEW: Get threat details
    function getThreat(bytes32 threatId) external view returns (string memory, Severity, address, uint256) {
        Threat memory t = threatLog[threatId];
        return (t.summary, t.severity, t.reporter, t.timestamp);
    }

    /// VIEW: Get user role
    function getUserRole(address user) external view returns (Role) {
        return roles[user];
    }
}
