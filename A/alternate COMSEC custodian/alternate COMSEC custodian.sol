// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract COMSECCustodian is AccessControl {
    bytes32 public constant PRIMARY_CUSTODIAN_ROLE = keccak256("PRIMARY_CUSTODIAN_ROLE");
    bytes32 public constant ALTERNATE_CUSTODIAN_ROLE = keccak256("ALTERNATE_CUSTODIAN_ROLE");

    bool public primaryActive = true;

    event PrimaryCustodianRevoked(address indexed by);
    event EmergencyActionTaken(address indexed by, string action);

    constructor(address primaryCustodian, address alternateCustodian) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(PRIMARY_CUSTODIAN_ROLE, primaryCustodian);
        _grantRole(ALTERNATE_CUSTODIAN_ROLE, alternateCustodian);
    }

    modifier onlyPrimary() {
        require(hasRole(PRIMARY_CUSTODIAN_ROLE, msg.sender), "Not primary custodian");
        require(primaryActive, "Primary disabled");
        _;
    }

    modifier onlyAlternateIfPrimaryDown() {
        require(hasRole(ALTERNATE_CUSTODIAN_ROLE, msg.sender), "Not alternate custodian");
        require(!primaryActive, "Primary custodian still active");
        _;
    }

    /// @notice Primary custodian performs a secure operation
    function performSecureOperation(string calldata op) external onlyPrimary {
        // Secure operation logic (e.g., key rotation)
        emit EmergencyActionTaken(msg.sender, op);
    }

    /// @notice Emergency fallback by alternate custodian
    function emergencyOverride(string calldata op) external onlyAlternateIfPrimaryDown {
        emit EmergencyActionTaken(msg.sender, op);
        // Emergency recovery or key restore
    }

    /// @notice Revoke primary custodian in crisis (admin only)
    function revokePrimaryCustodian() external onlyRole(DEFAULT_ADMIN_ROLE) {
        primaryActive = false;
        emit PrimaryCustodianRevoked(msg.sender);
    }

    /// @notice Restore primary role (e.g., after audit)
    function restorePrimaryCustodian() external onlyRole(DEFAULT_ADMIN_ROLE) {
        primaryActive = true;
    }

    /// @notice Check if primary is active
    function isPrimaryActive() external view returns (bool) {
        return primaryActive;
    }
}
