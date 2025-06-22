// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AttributeAdministrationPoint - Core contract to manage AVPs in ABAC systems

contract AttributeAdministrationPoint {
    address public superAdmin;

    enum AVPType { STRING, NUMBER, BOOLEAN }

    struct Attribute {
        string key;
        string stringValue;
        uint256 numberValue;
        bool boolValue;
        AVPType avpType;
        uint256 expiry;
        bool revoked;
    }

    mapping(address => Attribute[]) public userAttributes;
    mapping(address => bool) public delegatedIssuers;

    event AttributeAssigned(address indexed user, string key);
    event AttributeRevoked(address indexed user, string key);
    event IssuerUpdated(address indexed issuer, bool status);

    modifier onlyAdmin() {
        require(msg.sender == superAdmin || delegatedIssuers[msg.sender], "Unauthorized AAP");
        _;
    }

    constructor() {
        superAdmin = msg.sender;
    }

    function updateIssuer(address issuer, bool isActive) external {
        require(msg.sender == superAdmin, "Only superAdmin");
        delegatedIssuers[issuer] = isActive;
        emit IssuerUpdated(issuer, isActive);
    }

    function assignStringAVP(address user, string calldata key, string calldata value, uint256 expiry) external onlyAdmin {
        userAttributes[user].push(Attribute(key, value, 0, false, AVPType.STRING, expiry, false));
        emit AttributeAssigned(user, key);
    }

    function assignNumberAVP(address user, string calldata key, uint256 value, uint256 expiry) external onlyAdmin {
        userAttributes[user].push(Attribute(key, "", value, false, AVPType.NUMBER, expiry, false));
        emit AttributeAssigned(user, key);
    }

    function assignBoolAVP(address user, string calldata key, bool value, uint256 expiry) external onlyAdmin {
        userAttributes[user].push(Attribute(key, "", 0, value, AVPType.BOOLEAN, expiry, false));
        emit AttributeAssigned(user, key);
    }

    function revokeAVP(address user, uint index) external onlyAdmin {
        require(index < userAttributes[user].length, "Invalid index");
        userAttributes[user][index].revoked = true;
        emit AttributeRevoked(user, userAttributes[user][index].key);
    }

    function getAttributes(address user) external view returns (Attribute[] memory) {
        return userAttributes[user];
    }
}
