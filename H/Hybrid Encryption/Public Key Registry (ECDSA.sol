// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PublicKeyRegistry {
    mapping(address => bytes32) public publicKeys;

    function registerPublicKey(bytes32 pubKey) external {
        publicKeys[msg.sender] = pubKey;
    }

    function getPublicKey(address user) external view returns (bytes32) {
        return publicKeys[user];
    }
}
