// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AttributeManager - Manages user attributes for access control and verification

contract AttributeManager {
    struct Attribute {
        string key;
        string value;
        uint256 issuedAt;
        uint256 expiry;
        bool revoked;
    }

    address public admin;
    mapping(address => Attribute[]) public userAttributes;

    event AttributeAssigned(address indexed user, string key, string value);
    event AttributeRevoked(address indexed user, string key);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function assignAttribute(
        address user,
        string calldata key,
        string calldata value,
        uint256 expiry
    ) external onlyAdmin {
        userAttributes[user].push(Attribute({
            key: key,
            value: value,
            issuedAt: block.timestamp,
            expiry: expiry,
            revoked: false
        }));
        emit AttributeAssigned(user, key, value);
    }

    function revokeAttribute(address user, uint index) external onlyAdmin {
        require(index < userAttributes[user].length, "Invalid index");
        userAttributes[user][index].revoked = true;
        emit AttributeRevoked(user, userAttributes[user][index].key);
    }

    function verifyAttribute(
        address user,
        string calldata key,
        string calldata value
    ) external view returns (bool) {
        Attribute[] memory attrs = userAttributes[user];
        for (uint i = 0; i < attrs.length; i++) {
            if (
                !attrs[i].revoked &&
                keccak256(bytes(attrs[i].key)) == keccak256(bytes(key)) &&
                keccak256(bytes(attrs[i].value)) == keccak256(bytes(value)) &&
                (attrs[i].expiry == 0 || attrs[i].expiry > block.timestamp)
            ) {
                return true;
            }
        }
        return false;
    }

    function getAttributes(address user) external view returns (Attribute[] memory) {
        return userAttributes[user];
    }
}
