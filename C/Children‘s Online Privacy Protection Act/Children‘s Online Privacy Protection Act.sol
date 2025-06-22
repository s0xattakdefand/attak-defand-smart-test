// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IConsentVerifier {
    function isVerifiedChild(address user, bytes memory zkProof) external view returns (bool);
    function isParentApproved(address child, address parent) external view returns (bool);
}

contract COPPAProtectedContent {
    address public admin;
    IConsentVerifier public consentVerifier;

    mapping(address => bool) public approvedChildren;
    mapping(address => address) public childToParent;

    event ParentApproved(address indexed child, address indexed parent);
    event AccessGranted(address indexed user, uint256 timestamp);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can perform this action");
        _;
    }

    constructor(address _consentVerifier) {
        admin = msg.sender;
        consentVerifier = IConsentVerifier(_consentVerifier);
    }

    // Parent grants access to their child
    function approveChildAccess(address child) external {
        require(consentVerifier.isParentApproved(child, msg.sender), "Parent approval invalid");
        approvedChildren[child] = true;
        childToParent[child] = msg.sender;

        emit ParentApproved(child, msg.sender);
    }

    // Restricted access to child-friendly content
    function accessChildContent(bytes memory zkProof) external {
        require(consentVerifier.isVerifiedChild(msg.sender, zkProof), "User is not verified as a child");
        require(approvedChildren[msg.sender], "Parental approval required");

        emit AccessGranted(msg.sender, block.timestamp);

        // Child-specific content logic can go here
    }

    // Admin can revoke child access (if needed)
    function revokeAccess(address child) external onlyAdmin {
        approvedChildren[child] = false;
        childToParent[child] = address(0);
    }

    // View child-parent relationship
    function getParent(address child) external view returns (address) {
        return childToParent[child];
    }
}
