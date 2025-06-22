// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title CompromisedKeyList
/// @dev Maintains a list of compromised keys with enforcement capabilities
contract CompromisedKeyList {
    address public admin;

    mapping(address => bool) public isCompromised;
    mapping(address => uint256) public compromisedAt;

    event KeyMarked(address indexed compromisedKey, uint256 timestamp);
    event KeyRecovered(address indexed key);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /// @notice Mark a key as compromised
    function markCompromised(address key) external onlyAdmin {
        require(!isCompromised[key], "Already marked");
        isCompromised[key] = true;
        compromisedAt[key] = block.timestamp;
        emit KeyMarked(key, block.timestamp);
    }

    /// @notice Remove a key from the CKL (after rotation/recovery)
    function recoverKey(address key) external onlyAdmin {
        require(isCompromised[key], "Not compromised");
        isCompromised[key] = false;
        emit KeyRecovered(key);
    }

    /// @notice Check status of a key
    function isKeySafe(address key) public view returns (bool) {
        return !isCompromised[key];
    }
}

/// @title SecureContract
/// @dev Demonstrates enforcement of CKL protection on privileged functions
contract SecureContract {
    CompromisedKeyList public ckl;
    address public owner;

    constructor(address _ckl) {
        ckl = CompromisedKeyList(_ckl);
        owner = msg.sender;
    }

    modifier onlySafeOwner() {
        require(msg.sender == owner, "Not owner");
        require(ckl.isKeySafe(msg.sender), "Key compromised");
        _;
    }

    function sensitiveAction() external onlySafeOwner {
        // Critical function protected from compromised keys
    }
}
