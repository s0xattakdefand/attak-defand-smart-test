// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract AttributePracticeRegistry {
    address public admin;
    mapping(bytes32 => bool) public approvedAttributes; // keccak256("DAO:ROLE:issuer")
    mapping(address => mapping(bytes32 => bool)) public userAttributes; // user → attr → true
    mapping(bytes32 => string) public attributeDescriptions;

    event AttributeGranted(address indexed user, bytes32 attribute, string description);
    event AttributeRevoked(address indexed user, bytes32 attribute);

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    function registerAttribute(bytes32 attr, string calldata desc) external onlyAdmin {
        approvedAttributes[attr] = true;
        attributeDescriptions[attr] = desc;
    }

    function grantAttribute(address user, bytes32 attr) external onlyAdmin {
        require(approvedAttributes[attr], "Unknown attribute");
        userAttributes[user][attr] = true;
        emit AttributeGranted(user, attr, attributeDescriptions[attr]);
    }

    function revokeAttribute(address user, bytes32 attr) external onlyAdmin {
        userAttributes[user][attr] = false;
        emit AttributeRevoked(user, attr);
    }

    function hasAttribute(address user, bytes32 attr) external view returns (bool) {
        return userAttributes[user][attr];
    }

    function requireAttribute(address user, bytes32 attr) external view {
        require(userAttributes[user][attr], "Missing required attribute");
    }

    function getAttributeDescription(bytes32 attr) external view returns (string memory) {
        return attributeDescriptions[attr];
    }
}
