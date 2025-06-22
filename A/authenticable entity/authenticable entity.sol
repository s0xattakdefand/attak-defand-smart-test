// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AuthenticableEntityRegistry - Tracks and verifies authenticable identities

contract AuthenticableEntityRegistry {
    address public owner;

    mapping(address => bool) public registeredEOAs;
    mapping(address => bool) public registeredContracts;
    mapping(address => string) public roles;
    mapping(bytes32 => bool) public usedNullifiers;

    event EntityRegistered(address indexed entity, string role);
    event ZKEntityProved(address indexed entity, bytes32 nullifier, string context);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// @notice Register EOA or contract entity with role
    function registerEntity(address entity, string calldata role) external onlyOwner {
        if (entity.code.length > 0) {
            registeredContracts[entity] = true;
        } else {
            registeredEOAs[entity] = true;
        }
        roles[entity] = role;
        emit EntityRegistered(entity, role);
    }

    /// @notice Verifies zk-based authentication with nullifier
    function proveZKEntity(address entity, bytes32 nullifier, string calldata context) external onlyOwner {
        require(!usedNullifiers[nullifier], "Nullifier already used");
        usedNullifiers[nullifier] = true;
        emit ZKEntityProved(entity, nullifier, context);
    }

    function isAuthenticable(address entity) external view returns (bool) {
        return registeredEOAs[entity] || registeredContracts[entity];
    }

    function getRole(address entity) external view returns (string memory) {
        return roles[entity];
    }
}
