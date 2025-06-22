// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AttributeReferenceValidator - Verifies references to external attributes

interface IAttributeRegistry {
    function verifyAttribute(address user, string calldata key, string calldata value) external view returns (bool);
}

contract AttributeReferenceValidator {
    address public admin;

    struct AttributeReference {
        address registry;
        string key;
        string expectedValue;
        uint256 expiry;
        bool revoked;
    }

    mapping(address => AttributeReference[]) public userRefs;

    event AttributeReferenceAssigned(address indexed user, address registry, string key);
    event AttributeReferenceRevoked(address indexed user, string key);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function assignReference(
        address user,
        address registry,
        string calldata key,
        string calldata expectedValue,
        uint256 expiry
    ) external onlyAdmin {
        userRefs[user].push(AttributeReference({
            registry: registry,
            key: key,
            expectedValue: expectedValue,
            expiry: expiry,
            revoked: false
        }));

        emit AttributeReferenceAssigned(user, registry, key);
    }

    function revokeReference(address user, uint index) external onlyAdmin {
        require(index < userRefs[user].length, "Invalid index");
        userRefs[user][index].revoked = true;
        emit AttributeReferenceRevoked(user, userRefs[user][index].key);
    }

    function validateReference(address user, uint index) external view returns (bool) {
        require(index < userRefs[user].length, "Invalid ref");
        AttributeReference memory ref = userRefs[user][index];

        if (ref.revoked || (ref.expiry > 0 && ref.expiry < block.timestamp)) {
            return false;
        }

        return IAttributeRegistry(ref.registry).verifyAttribute(user, ref.key, ref.expectedValue);
    }

    function getUserReferences(address user) external view returns (AttributeReference[] memory) {
        return userRefs[user];
    }
}
