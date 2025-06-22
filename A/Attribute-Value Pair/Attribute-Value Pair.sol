// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AVPRegistry - Manages Attribute-Value Pairs (AVPs) for access control and user verification

contract AVPRegistry {
    address public admin;

    enum AVPType { STRING, NUMBER, BOOLEAN }

    struct AVP {
        string key;
        string stringValue;
        uint256 numberValue;
        bool boolValue;
        AVPType avpType;
        uint256 expiry;
        bool revoked;
    }

    mapping(address => AVP[]) public userAVPs;

    event AVPAssigned(address indexed user, string key, string value);
    event AVPRevoked(address indexed user, string key);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function assignStringAVP(address user, string calldata key, string calldata value, uint256 expiry) external onlyAdmin {
        userAVPs[user].push(AVP(key, value, 0, false, AVPType.STRING, expiry, false));
        emit AVPAssigned(user, key, value);
    }

    function assignNumberAVP(address user, string calldata key, uint256 value, uint256 expiry) external onlyAdmin {
        userAVPs[user].push(AVP(key, "", value, false, AVPType.NUMBER, expiry, false));
        emit AVPAssigned(user, key, uintToStr(value));
    }

    function assignBoolAVP(address user, string calldata key, bool value, uint256 expiry) external onlyAdmin {
        userAVPs[user].push(AVP(key, "", 0, value, AVPType.BOOLEAN, expiry, false));
        emit AVPAssigned(user, key, value ? "true" : "false");
    }

    function revokeAVP(address user, uint index) external onlyAdmin {
        require(index < userAVPs[user].length, "Invalid index");
        userAVPs[user][index].revoked = true;
        emit AVPRevoked(user, userAVPs[user][index].key);
    }

    function verifyStringAVP(address user, string calldata key, string calldata expected) public view returns (bool) {
        for (uint i = 0; i < userAVPs[user].length; i++) {
            AVP memory a = userAVPs[user][i];
            if (
                !a.revoked &&
                a.avpType == AVPType.STRING &&
                keccak256(bytes(a.key)) == keccak256(bytes(key)) &&
                keccak256(bytes(a.stringValue)) == keccak256(bytes(expected)) &&
                (a.expiry == 0 || a.expiry > block.timestamp)
            ) return true;
        }
        return false;
    }

    function verifyNumberAVP(address user, string calldata key, uint256 minValue) public view returns (bool) {
        for (uint i = 0; i < userAVPs[user].length; i++) {
            AVP memory a = userAVPs[user][i];
            if (
                !a.revoked &&
                a.avpType == AVPType.NUMBER &&
                keccak256(bytes(a.key)) == keccak256(bytes(key)) &&
                a.numberValue >= minValue &&
                (a.expiry == 0 || a.expiry > block.timestamp)
            ) return true;
        }
        return false;
    }

    function verifyBoolAVP(address user, string calldata key) public view returns (bool) {
        for (uint i = 0; i < userAVPs[user].length; i++) {
            AVP memory a = userAVPs[user][i];
            if (
                !a.revoked &&
                a.avpType == AVPType.BOOLEAN &&
                keccak256(bytes(a.key)) == keccak256(bytes(key)) &&
                a.boolValue &&
                (a.expiry == 0 || a.expiry > block.timestamp)
            ) return true;
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
            bstr[--k] = bytes1(uint8(48 + v % 10));
            v /= 10;
        }
        str = string(bstr);
    }
}
