// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Unauthorized Application Attack, Bypass Allowlist Attack, Privilege Escalation Attack
/// Defense Types: Strict Allowlist Enforcement, Immutable/Admin Controlled Allowlist, Audit and Monitoring

contract ApplicationAllowlisting {
    address public admin;
    mapping(address => bool) public allowlistedApplications;

    event ApplicationAllowlisted(address indexed app);
    event ApplicationRemoved(address indexed app);
    event AttackDetected(address indexed attacker, string reason);

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin allowed");
        _;
    }

    modifier onlyAllowlisted() {
        if (!allowlistedApplications[msg.sender]) {
            emit AttackDetected(msg.sender, "Unauthorized application access attempt");
            revert("Application not allowlisted");
        }
        _;
    }

    /// ATTACK Simulation: Unauthorized application access
    function attackUnauthorizedApplication() external view onlyAllowlisted returns (string memory) {
        return "You should not see this if not allowlisted.";
    }

    /// DEFENSE: Admin allowlists an application (dApp, contract, wallet)
    function allowlistApplication(address app) external onlyAdmin {
        allowlistedApplications[app] = true;
        emit ApplicationAllowlisted(app);
    }

    /// DEFENSE: Admin removes an application from allowlist
    function removeApplication(address app) external onlyAdmin {
        allowlistedApplications[app] = false;
        emit ApplicationRemoved(app);
    }

    /// DEFENSE: Protected function only for allowlisted apps
    function protectedFunction() external onlyAllowlisted returns (string memory) {
        return "Allowlisted application access granted.";
    }

    /// View application allowlist status
    function isAllowlisted(address app) external view returns (bool) {
        return allowlistedApplications[app];
    }
}
