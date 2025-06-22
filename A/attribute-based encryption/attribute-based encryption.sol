// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Attribute Forgery Attack, Policy Bypass Attack, Overbroad Attribute Assignment
/// Defense Types: Attribute Verification Binding, Strict Policy Evaluation, Granular Assignment

contract AttributeBasedAccessControl {
    address public admin;

    enum Attribute { NONE, DOCTOR, ENGINEER, RESEARCHER, ADMIN, ASIA, EUROPE }

    struct UserAttributes {
        mapping(Attribute => bool) hasAttribute;
    }

    mapping(address => UserAttributes) internal userAttrs;

    event AttributeAssigned(address indexed user, Attribute attribute);
    event AccessGranted(address indexed user, string resource);
    event AttackDetected(address indexed attacker, string reason);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can assign");
        _;
    }

    constructor() {
        admin = msg.sender;
        _assign(msg.sender, Attribute.ADMIN);
    }

    /// ATTACK Simulation: Try to access resource without satisfying policy
    function attackUnauthorizedAccess() external {
        if (!_has(msg.sender, Attribute.DOCTOR) || !_has(msg.sender, Attribute.ASIA)) {
            emit AttackDetected(msg.sender, "Policy not satisfied");
            revert("Access denied");
        }
    }

    /// DEFENSE: Assign attribute to a user (admin only)
    function assignAttribute(address user, Attribute attr) external onlyAdmin {
        _assign(user, attr);
    }

    /// DEFENSE: Simulated resource access with ABE-style policy (e.g., must be DOCTOR AND ASIA)
    function accessProtectedResource() external {
        require(_has(msg.sender, Attribute.DOCTOR), "Must be a doctor");
        require(_has(msg.sender, Attribute.ASIA), "Must be in Asia");

        emit AccessGranted(msg.sender, "EncryptedMedicalData");
    }

    /// Internal assign
    function _assign(address user, Attribute attr) internal {
        userAttrs[user].hasAttribute[attr] = true;
        emit AttributeAssigned(user, attr);
    }

    /// Internal check
    function _has(address user, Attribute attr) internal view returns (bool) {
        return userAttrs[user].hasAttribute[attr];
    }

    /// View if user has attribute
    function hasAttribute(address user, Attribute attr) external view returns (bool) {
        return _has(user, attr);
    }
}
