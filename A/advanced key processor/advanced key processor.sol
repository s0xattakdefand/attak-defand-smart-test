// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Advanced Key Processor — Key Hash Registry, Validator, and Auditor
contract AdvancedKeyProcessor {
    address public admin;

    struct KeyInfo {
        bytes32 keyHash;       // keccak256(key)
        uint256 registeredAt;
        bool active;
    }

    mapping(address => KeyInfo[]) public keys;
    event KeyRegistered(address indexed user, uint256 index, bytes32 keyHash);
    event KeyValidated(address indexed user, uint256 index);
    event KeyRotated(address indexed user, uint256 oldIndex, bytes32 newKeyHash);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /// Register a new key hash for user
    function registerKey(bytes32 keyHash) external {
        keys[msg.sender].push(KeyInfo(keyHash, block.timestamp, true));
        emit KeyRegistered(msg.sender, keys[msg.sender].length - 1, keyHash);
    }

    /// Validate key (offchain) against registered hash
    function validateKey(uint256 index, bytes32 providedKeyHash) external view returns (bool) {
        KeyInfo memory k = keys[msg.sender][index];
        require(k.active, "Key inactive");
        return k.keyHash == providedKeyHash;
    }

    /// Rotate to a new key (invalidate old, add new)
    function rotateKey(uint256 oldIndex, bytes32 newKeyHash) external {
        keys[msg.sender][oldIndex].active = false;
        keys[msg.sender].push(KeyInfo(newKeyHash, block.timestamp, true));
        emit KeyRotated(msg.sender, oldIndex, newKeyHash);
    }

    function getKeyInfo(address user, uint256 index) external view returns (KeyInfo memory) {
        return keys[user][index];
    }
}
