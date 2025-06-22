// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AttributeBasedAccess - Enforces attribute-based authorization on smart contract functions

contract AttributeBasedAccess {
    address public admin;

    enum ValueType { STRING, NUMBER, BOOLEAN }

    struct Attribute {
        string key;
        string stringValue;
        uint256 numberValue;
        bool boolValue;
        ValueType valueType;
        uint256 expiry;
        bool revoked;
    }

    mapping(address => Attribute[]) public userAttributes;

    event AttributeSet(address indexed user, string key);
    event AttributeRevoked(address indexed user, string key);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    // Attribute assignment
    function setAttribute(
        address user,
        string calldata key,
        string calldata stringValue,
        uint256 numberValue,
        bool boolValue,
        ValueType valueType,
        uint256 expiry
    ) external onlyAdmin {
        userAttributes[user].push(Attribute({
            key: key,
            stringValue: stringValue,
            numberValue: numberValue,
            boolValue: boolValue,
            valueType: valueType,
            expiry: expiry,
            revoked: false
        }));
        emit AttributeSet(user, key);
    }

    function revokeAttribute(address user, uint index) external onlyAdmin {
        require(index < userAttributes[user].length, "Invalid index");
        userAttributes[user][index].revoked = true;
        emit AttributeRevoked(user, userAttributes[user][index].key);
    }

    // ABA enforcement
    function requireRole(address user, string calldata role) public view returns (bool) {
        Attribute[] memory attrs = userAttributes[user];
        for (uint i = 0; i < attrs.length; i++) {
            if (
                !attrs[i].revoked &&
                attrs[i].valueType == ValueType.STRING &&
                keccak256(bytes(attrs[i].key)) == keccak256("Role") &&
                keccak256(bytes(attrs[i].stringValue)) == keccak256(bytes(role)) &&
                (attrs[i].expiry == 0 || attrs[i].expiry > block.timestamp)
            ) {
                return true;
            }
        }
        return false;
    }

    function requireKYC(address user) public view returns (bool) {
        Attribute[] memory attrs = userAttributes[user];
        for (uint i = 0; i < attrs.length; i++) {
            if (
                !attrs[i].revoked &&
                attrs[i].valueType == ValueType.BOOLEAN &&
                keccak256(bytes(attrs[i].key)) == keccak256("KYC") &&
                attrs[i].boolValue == true &&
                (attrs[i].expiry == 0 || attrs[i].expiry > block.timestamp)
            ) {
                return true;
            }
        }
        return false;
    }

    function requireScoreAbove(address user, uint256 threshold) public view returns (bool) {
        Attribute[] memory attrs = userAttributes[user];
        for (uint i = 0; i < attrs.length; i++) {
            if (
                !attrs[i].revoked &&
                attrs[i].valueType == ValueType.NUMBER &&
                keccak256(bytes(attrs[i].key)) == keccak256("Score") &&
                attrs[i].numberValue >= threshold &&
                (attrs[i].expiry == 0 || attrs[i].expiry > block.timestamp)
            ) {
                return true;
            }
        }
        return false;
    }

    // Example protected function
    function gatedFunction() external {
        require(requireRole(msg.sender, "Moderator"), "Not authorized (Role)");
        require(requireKYC(msg.sender), "Not authorized (KYC)");
        require(requireScoreAbove(msg.sender, 100), "Score too low");
        // Access granted
    }
}
