// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * KEY LIFECYCLE MANAGER
 * — Manages the lifecycle states of cryptographic keys in accordance
 *   with NIST SP 800-152 definitions.
 *
 * Specifically covers the “Deactivated” state:
 *   “A lifecycle state of a key whereby the key is no longer to be used
 *    for applying cryptographic protection. Processing already protected
 *    information may still be performed.”
 */

abstract contract Ownable {
    address private _owner;
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor() {
        _owner = msg.sender;
        emit OwnershipTransferred(address(0), _owner);
    }

    modifier onlyOwner() {
        require(msg.sender == _owner, "Ownable: caller is not owner");
        _;
    }

    function owner() public view returns (address) {
        return _owner;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}

contract KeyLifecycleManager is Ownable {
    enum State { Active, Deactivated }

    struct KeyInfo {
        State   state;
        uint256 createdAt;
        uint256 deactivatedAt;
        address createdBy;
        address deactivatedBy;
    }

    uint256 public nextKeyId;
    mapping(uint256 => KeyInfo) public keys;

    event KeyCreated(uint256 indexed keyId, address indexed createdBy, uint256 timestamp);
    event KeyDeactivated(uint256 indexed keyId, address indexed deactivatedBy, uint256 timestamp);

    /// @notice Owner creates a new key record in Active state
    /// @return keyId The identifier of the newly created key
    function createKey() external onlyOwner returns (uint256 keyId) {
        keyId = nextKeyId++;
        keys[keyId] = KeyInfo({
            state:         State.Active,
            createdAt:     block.timestamp,
            deactivatedAt: 0,
            createdBy:     msg.sender,
            deactivatedBy: address(0)
        });
        emit KeyCreated(keyId, msg.sender, block.timestamp);
    }

    /// @notice Owner deactivates an Active key
    /// @param keyId The identifier of the key to deactivate
    function deactivateKey(uint256 keyId) external onlyOwner {
        KeyInfo storage k = keys[keyId];
        require(k.state == State.Active, "Key is not active");
        k.state = State.Deactivated;
        k.deactivatedAt = block.timestamp;
        k.deactivatedBy = msg.sender;
        emit KeyDeactivated(keyId, msg.sender, block.timestamp);
    }

    /// @notice Check whether a key is active
    function isActive(uint256 keyId) external view returns (bool) {
        return keys[keyId].state == State.Active;
    }

    /// @notice Retrieve full lifecycle info for a key
    function getKeyInfo(uint256 keyId)
        external
        view
        returns (
            State   state,
            uint256 createdAt,
            uint256 deactivatedAt,
            address createdBy,
            address deactivatedBy
        )
    {
        KeyInfo storage k = keys[keyId];
        return (k.state, k.createdAt, k.deactivatedAt, k.createdBy, k.deactivatedBy);
    }
}
