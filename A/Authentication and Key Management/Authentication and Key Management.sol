// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract AuthKeyManagement {
    struct KeyData {
        bytes32 pubKeyHash;
        uint256 issuedAt;
        bool revoked;
    }

    mapping(address => KeyData) public keys;
    mapping(bytes32 => bool) public blacklist;

    event KeyRegistered(address indexed user, bytes32 pubKeyHash);
    event KeyRevoked(address indexed user, bytes32 pubKeyHash);
    event KeyRotated(address indexed user, bytes32 oldPubKeyHash, bytes32 newPubKeyHash);

    modifier onlyValidKey(address user, bytes32 pubKeyHash) {
        require(keys[user].pubKeyHash == pubKeyHash, "Invalid public key");
        require(!keys[user].revoked, "Key is revoked");
        require(!blacklist[pubKeyHash], "Key is blacklisted");
        _;
    }

    /// @notice Register a new public key securely
    function registerKey(bytes32 pubKeyHash) external {
        require(keys[msg.sender].pubKeyHash == bytes32(0), "Key already registered");
        keys[msg.sender] = KeyData({
            pubKeyHash: pubKeyHash,
            issuedAt: block.timestamp,
            revoked: false
        });

        emit KeyRegistered(msg.sender, pubKeyHash);
    }

    /// @notice Rotate (update) an existing public key
    function rotateKey(bytes32 newPubKeyHash) external {
        require(keys[msg.sender].pubKeyHash != bytes32(0), "No existing key registered");
        bytes32 oldPubKeyHash = keys[msg.sender].pubKeyHash;
        blacklist[oldPubKeyHash] = true; // Automatically blacklist old key
        keys[msg.sender] = KeyData({
            pubKeyHash: newPubKeyHash,
            issuedAt: block.timestamp,
            revoked: false
        });

        emit KeyRotated(msg.sender, oldPubKeyHash, newPubKeyHash);
    }

    /// @notice Immediately revoke a compromised key
    function revokeKey() external {
        require(keys[msg.sender].pubKeyHash != bytes32(0), "No key registered");
        keys[msg.sender].revoked = true;
        blacklist[keys[msg.sender].pubKeyHash] = true;

        emit KeyRevoked(msg.sender, keys[msg.sender].pubKeyHash);
    }

    /// @notice Authenticate user securely via provided pubKeyHash
    function authenticate(bytes32 pubKeyHash) external view onlyValidKey(msg.sender, pubKeyHash) returns (bool) {
        return true;
    }

    /// @notice Check if a key is revoked or blacklisted
    function isKeyRevokedOrBlacklisted(bytes32 pubKeyHash) external view returns (bool) {
        return blacklist[pubKeyHash];
    }
}
