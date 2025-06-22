// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Committee Forgery, Attribute Overreach, Unrevoked Attribute Exploit
/// Defense Types: Committee Registry, Logging, Revocation Enforcement

contract AASCRegistry {
    address public rootAdmin;

    mapping(address => bool) public isCommitteeMember;
    mapping(address => mapping(string => bool)) public userAttributes;
    mapping(address => mapping(string => bool)) public userPermissions;

    event CommitteeMemberAdded(address indexed member);
    event CommitteeMemberRemoved(address indexed member);
    event AttributeGranted(address indexed user, string attribute);
    event PermissionGranted(address indexed user, string permission);
    event AttributeRevoked(address indexed user, string attribute);
    event PermissionRevoked(address indexed user, string permission);
    event AttackDetected(address indexed attacker, string reason);

    modifier onlyRoot() {
        require(msg.sender == rootAdmin, "Only root admin");
        _;
    }

    modifier onlyCommittee() {
        if (!isCommitteeMember[msg.sender]) {
            emit AttackDetected(msg.sender, "Unauthorized committee impersonation");
            revert("Not authorized as committee");
        }
        _;
    }

    constructor() {
        rootAdmin = msg.sender;
        isCommitteeMember[msg.sender] = true;
        emit CommitteeMemberAdded(msg.sender);
    }

    /// DEFENSE: Root adds new committee member
    function addCommitteeMember(address member) external onlyRoot {
        isCommitteeMember[member] = true;
        emit CommitteeMemberAdded(member);
    }

    /// DEFENSE: Root removes committee member
    function removeCommitteeMember(address member) external onlyRoot {
        isCommitteeMember[member] = false;
        emit CommitteeMemberRemoved(member);
    }

    /// DEFENSE: Committee grants attribute to a user
    function grantAttribute(address user, string calldata attr) external onlyCommittee {
        userAttributes[user][attr] = true;
        emit AttributeGranted(user, attr);
    }

    /// DEFENSE: Committee grants permission
    function grantPermission(address user, string calldata perm) external onlyCommittee {
        userPermissions[user][perm] = true;
        emit PermissionGranted(user, perm);
    }

    /// DEFENSE: Revoke access or attribute
    function revokeAttribute(address user, string calldata attr) external onlyCommittee {
        userAttributes[user][attr] = false;
        emit AttributeRevoked(user, attr);
    }

    function revokePermission(address user, string calldata perm) external onlyCommittee {
        userPermissions[user][perm] = false;
        emit PermissionRevoked(user, perm);
    }

    /// ATTACK Simulation: Forged grant
    function attackGrantFakeAttribute(address user, string calldata attr) external {
        userAttributes[user][attr] = true;
        emit AttackDetected(msg.sender, "Forged attribute issuance");
        revert("Unauthorized attribute grant");
    }

    /// Public check
    function hasAttribute(address user, string calldata attr) external view returns (bool) {
        return userAttributes[user][attr];
    }

    function hasPermission(address user, string calldata perm) external view returns (bool) {
        return userPermissions[user][perm];
    }
}
