// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Another approach: user sends encrypted messages, 
 * watchers can't see plaintext in logs => partial confidentiality
 */
contract OnChainEchoEncryption {
    event EchoEncrypted(address indexed sender, bytes encryptedMessage);

    function echoEncrypted(bytes calldata cipher) external {
        // ephemeral encryption is done off-chain, we only store the cipher
        emit EchoEncrypted(msg.sender, cipher);
    }
}
