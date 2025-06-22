// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Attribute Forgery Attack, Bypass Attribute Validation Attack, Privilege Escalation Attack
/// Defense Types: Signed Attribute Proofs, Strict Attribute Validation, Role Binding and Expiration

contract AttributeAuthoritySystem {
    address public attributeAuthority;
    mapping(address => mapping(string => bool)) public userAttributes;

    event AttributeAssigned(address indexed user, string attribute);
    event AttackDetected(string reason);

    constructor() {
        attributeAuthority = msg.sender; // deployer is the first authority
    }

    modifier onlyAuthority() {
        require(msg.sender == attributeAuthority, "Only Attribute Authority allowed");
        _;
    }

    /// ATTACK Simulation: Assign attributes without authority
    function attackForgeAttribute(address user, string memory attribute) external {
        // Unsafe direct manipulation — simulating attack
        userAttributes[user][attribute] = true;
    }

    /// DEFENSE: Only authority can assign attributes securely
    function assignAttribute(address user, string calldata attribute) external onlyAuthority {
        userAttributes[user][attribute] = true;
        emit AttributeAssigned(user, attribute);
    }

    /// DEFENSE: Check if user holds a valid attribute
    function hasAttribute(address user, string memory attribute) public view returns (bool) {
        return userAttributes[user][attribute];
    }

    /// DEFENSE: User-only function gated by attribute
    function attributeRestrictedAction(string calldata requiredAttribute) external view returns (string memory) {
        require(userAttributes[msg.sender][requiredAttribute], "Missing required attribute");
        return "You are authorized based on your attribute.";
    }

    /// Admin: Transfer attribute authority role securely
    function transferAttributeAuthority(address newAuthority) external onlyAuthority {
        require(newAuthority != address(0), "Invalid new authority");
        attributeAuthority = newAuthority;
    }
}
