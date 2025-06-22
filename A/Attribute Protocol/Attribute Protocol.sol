// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AttributeProtocol - On-chain attribute verification system for identity, role, or permissions

contract AttributeProtocol {
    address public admin;

    struct Attribute {
        string key;             // e.g. "KYC", "Role", "Age", "Country"
        string value;           // e.g. "Approved", "Admin", "21", "KH"
        address issuer;         // Trusted attribute signer
        uint256 issuedAt;
        uint256 expiry;         // 0 = no expiry
        bool revoked;
    }

    mapping(address => Attribute[]) public userAttributes;

    event AttributeAssigned(address indexed user, string key, string value, address issuer);
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
            issuer: msg.sender,
            issuedAt: block.timestamp,
            expiry: expiry,
            revoked: false
        }));

        emit AttributeAssigned(user, key, value, msg.sender);
    }

    function revokeAttribute(address user, uint256 index) external onlyAdmin {
        require(index < userAttributes[user].length, "Invalid index");
        userAttributes[user][index].revoked = true;
        emit AttributeRevoked(user, userAttributes[user][index].key);
    }

    function verifyAttribute(
        address user,
        string calldata key,
        string calldata expectedValue
    ) external view returns (bool) {
        Attribute[] memory attrs = userAttributes[user];
        for (uint i = 0; i < attrs.length; i++) {
            Attribute memory a = attrs[i];
            if (
                keccak256(bytes(a.key)) == keccak256(bytes(key)) &&
                keccak256(bytes(a.value)) == keccak256(bytes(expectedValue)) &&
                !a.revoked &&
                (a.expiry == 0 || a.expiry > block.timestamp)
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
