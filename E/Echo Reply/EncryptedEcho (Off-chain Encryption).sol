// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Other approach:
 * The user or front-end encrypts the data first, 
 * only storing ciphertext on-chain. 
 */
contract EncryptedEcho {
    event EchoedCiphertext(address indexed sender, bytes cipher);

    function echoEncrypted(bytes calldata cipher) external {
        // We only store/log the ciphertext
        // Observers see no plaintext, can't read the real message
        emit EchoedCiphertext(msg.sender, cipher);
    }
}
