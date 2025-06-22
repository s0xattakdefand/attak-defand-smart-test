// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AttributeValueStore - Securely stores and validates user attribute values

contract AttributeValueStore {
    address public admin;

    enum ValueType { STRING, NUMBER, BOOLEAN }

    struct AttributeValue {
        string key;
        string stringValue;
        uint256 numberValue;
        bool boolValue;
        ValueType valueType;
        uint256 expiry;
        bool revoked;
    }

    mapping(address => AttributeValue[]) public userValues;

    event AttributeSet(address indexed user, string key, string value);
    event AttributeRevoked(address indexed user, string key);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function setStringValue(address user, string calldata key, string calldata value, uint256 expiry) external onlyAdmin {
        userValues[user].push(AttributeValue(key, value, 0, false, ValueType.STRING, expiry, false));
        emit AttributeSet(user, key, value);
    }

    function setNumberValue(address user, string calldata key, uint256 value, uint256 expiry) external onlyAdmin {
        userValues[user].push(AttributeValue(key, "", value, false, ValueType.NUMBER, expiry, false));
        emit AttributeSet(user, key, uintToStr(value));
    }

    function setBoolValue(address user, string calldata key, bool value, uint256 expiry) external onlyAdmin {
        userValues[user].push(AttributeValue(key, "", 0, value, ValueType.BOOLEAN, expiry, false));
        emit AttributeSet(user, key, value ? "true" : "false");
    }

    function revokeValue(address user, uint index) external onlyAdmin {
        require(index < userValues[user].length, "Invalid index");
        userValues[user][index].revoked = true;
        emit AttributeRevoked(user, userValues[user][index].key);
    }

    function validateValue(address user, string calldata key, string calldata expected) external view returns (bool) {
        for (uint i = 0; i < userValues[user].length; i++) {
            AttributeValue memory val = userValues[user][i];
            if (
                !val.revoked &&
                val.valueType == ValueType.STRING &&
                keccak256(bytes(val.key)) == keccak256(bytes(key)) &&
                keccak256(bytes(val.stringValue)) == keccak256(bytes(expected)) &&
                (val.expiry == 0 || val.expiry > block.timestamp)
            ) {
                return true;
            }
        }
        return false;
    }

    function uintToStr(uint v) internal pure returns (string memory str) {
        if (v == 0) return "0";
        uint j = v;
        uint len;
        while (j != 0) {
            len++;
            j /= 10;
        }
        bytes memory bstr = new bytes(len);
        uint k = len;
        while (v != 0) {
            k = k - 1;
            bstr[k] = bytes1(uint8(48 + v % 10));
            v /= 10;
        }
        str = string(bstr);
    }
}
