// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AttributeDisclosureVerifier - Manages and verifies user attribute disclosures

contract AttributeDisclosureVerifier {
    address public admin;

    struct Attribute {
        string key;
        string value;
        uint256 expiry;
        bool revoked;
    }

    mapping(address => Attribute[]) public disclosedAttributes;
    mapping(string => bool) public allowedKeys; // Allow only certain keys to be disclosed

    event AttributeDisclosed(address indexed user, string key, string value);
    event AttributeRevoked(address indexed user, string key);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    constructor() {
        admin = msg.sender;
        allowedKeys["KYC"] = true;
        allowedKeys["Role"] = true;
        allowedKeys["Country"] = true;
        allowedKeys["Age"] = true;
    }

    function discloseAttribute(address user, string calldata key, string calldata value, uint256 expiry) external onlyAdmin {
        require(allowedKeys[key], "Disclosure not allowed for this key");
        disclosedAttributes[user].push(Attribute(key, value, expiry, false));
        emit AttributeDisclosed(user, key, value);
    }

    function revokeAttribute(address user, uint index) external onlyAdmin {
        require(index < disclosedAttributes[user].length, "Invalid index");
        disclosedAttributes[user][index].revoked = true;
        emit AttributeRevoked(user, disclosedAttributes[user][index].key);
    }

    function validateDisclosure(address user, string calldata key, string calldata value) external view returns (bool) {
        Attribute[] memory attrs = disclosedAttributes[user];
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

    function restrictDisclosureKey(string calldata key, bool allowed) external onlyAdmin {
        allowedKeys[key] = allowed;
    }
}
