// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Another approach (Other):
 * Partial or 'hybrid' encryption, 
 * user might store a short public key for ephemeral encryption,
 * but full data encryption is done off-chain.
 */
contract HybridEncryptionPartial {
    // user => ephemeral public key or something
    mapping(address => bytes32) public userPubKey;

    event PubKeySet(address indexed user, bytes32 pubKey);

    function setPubKey(bytes32 pubKey) external {
        userPubKey[msg.sender] = pubKey;
        emit PubKeySet(msg.sender, pubKey);
    }

    // The actual encryption is still done off-chain, 
    // but we reference userPubKey to do ephemeral key exchange, etc.
}
