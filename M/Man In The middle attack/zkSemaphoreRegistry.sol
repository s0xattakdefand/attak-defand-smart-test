// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @title zkSemaphoreRegistry - Simple identity whitelist for MAC/DAO usage
contract zkSemaphoreRegistry {
    mapping(bytes32 => bool) public validIdentities;
    address public admin;

    constructor() {
        admin = msg.sender;
    }

    function addIdentity(bytes32 zkHash) external {
        require(msg.sender == admin, "Only admin");
        validIdentities[zkHash] = true;
    }

    function isValid(bytes32 zkHash) external view returns (bool) {
        return validIdentities[zkHash];
    }
}
