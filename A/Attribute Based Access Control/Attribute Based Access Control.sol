// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Attribute Forgery, Policy Bypass, Stale Replay
/// Defense Types: Trusted Issuance, Policy Enforcement, Revocation

contract AttributeBasedAccessControl {
    address public admin;

    enum Attribute {
        NONE,
        DOCTOR,
        ENGINEER,
        ASIA,
        EU,
        VERIFIED
    }

    mapping(address => mapping(Attribute => bool)) public userAttributes;

    event AttributeGranted(address indexed user, Attribute attr);
    event AttributeRevoked(address indexed user, Attribute attr);
    event AccessGranted(address indexed user, string action);
    event AttackDetected(address indexed user, string reason);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
        _grant(msg.sender, Attribute.VERIFIED);
    }

    /// DEFENSE: Admin grants attribute to user
    function grantAttribute(address user, Attribute attr) external onlyAdmin {
        _grant(user, attr);
    }

    function _grant(address user, Attribute attr) internal {
        userAttributes[user][attr] = true;
        emit AttributeGranted(user, attr);
    }

    /// DEFENSE: Admin revokes attribute
    function revokeAttribute(address user, Attribute attr) external onlyAdmin {
        userAttributes[user][attr] = false;
        emit AttributeRevoked(user, attr);
    }

    /// DEFENSE: ABAC protected resource — requires multiple attributes
    function accessMedicalData() external {
        if (
            !userAttributes[msg.sender][Attribute.DOCTOR] ||
            !userAttributes[msg.sender][Attribute.ASIA] ||
            !userAttributes[msg.sender][Attribute.VERIFIED]
        ) {
            emit AttackDetected(msg.sender, "ABAC policy not satisfied");
            revert("Access denied: missing required attributes");
        }

        emit AccessGranted(msg.sender, "MedicalDataAccess");
    }

    /// ATTACK Simulation: Directly toggle attributes without admin
    function attackFakeAttribute(Attribute attr) external {
        userAttributes[msg.sender][attr] = true;
        emit AttackDetected(msg.sender, "Attribute forgery attempt");
        revert("Unauthorized attribute assignment");
    }

    /// View user’s attribute
    function hasAttribute(address user, Attribute attr) external view returns (bool) {
        return userAttributes[user][attr];
    }
}
