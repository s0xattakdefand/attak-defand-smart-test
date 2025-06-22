// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AttributeBundleManager - Assigns and verifies compound attribute bundles for access control

contract AttributeBundleManager {
    address public admin;

    struct Attribute {
        string key;
        string value;
        uint256 expiry;
        bool revoked;
    }

    struct Bundle {
        string name;
        Attribute[] attributes;
        uint256 createdAt;
        uint256 expiry;
        bool revoked;
    }

    mapping(address => Bundle[]) public userBundles;

    event BundleAssigned(address indexed user, string name);
    event BundleRevoked(address indexed user, string name);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function assignBundle(
        address user,
        string calldata name,
        Attribute[] calldata attrs,
        uint256 expiry
    ) external onlyAdmin {
        Bundle storage b = userBundles[user].push();
        b.name = name;
        b.createdAt = block.timestamp;
        b.expiry = expiry;
        b.revoked = false;

        for (uint i = 0; i < attrs.length; i++) {
            b.attributes.push(attrs[i]);
        }

        emit BundleAssigned(user, name);
    }

    function revokeBundle(address user, uint index) external onlyAdmin {
        require(index < userBundles[user].length, "Invalid index");
        userBundles[user][index].revoked = true;
        emit BundleRevoked(user, userBundles[user][index].name);
    }

    function verifyBundle(
        address user,
        uint index,
        string[] calldata keys,
        string[] calldata values
    ) external view returns (bool) {
        require(index < userBundles[user].length, "Invalid bundle");
        Bundle storage b = userBundles[user][index];
        require(!b.revoked, "Revoked");
        require(b.expiry == 0 || b.expiry > block.timestamp, "Expired");

        for (uint i = 0; i < keys.length; i++) {
            bool found = false;
            for (uint j = 0; j < b.attributes.length; j++) {
                if (
                    keccak256(bytes(b.attributes[j].key)) == keccak256(bytes(keys[i])) &&
                    keccak256(bytes(b.attributes[j].value)) == keccak256(bytes(values[i])) &&
                    !b.attributes[j].revoked &&
                    (b.attributes[j].expiry == 0 || b.attributes[j].expiry > block.timestamp)
                ) {
                    found = true;
                    break;
                }
            }
            if (!found) return false;
        }
        return true;
    }

    function getBundles(address user) external view returns (Bundle[] memory) {
        return userBundles[user];
    }
}
