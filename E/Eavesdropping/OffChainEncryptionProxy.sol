// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Another approach: user encrypts data off-chain, 
 * sends only an encrypted blob or pointer on-chain. 
 * Eavesdroppers see ciphertext, not the actual value.
 */
contract OffChainEncryptionProxy {
    mapping(address => bytes) public encryptedData;

    function storeEncrypted(bytes calldata cipher) external {
        // user has ciphertext from an off-chain encryption
        // watchers can read it, but can't easily decrypt
        encryptedData[msg.sender] = cipher;
    }
}
