// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * DEFENSE TYPE:
 * Real encryption done off-chain with a strong cipher (AES, etc.).
 * The user only stores the resulting ciphertext or a hash on-chain.
 * No keys or raw encryption logic in the contract => no direct leaks.
 */
contract CiphertextReference {
    // user => array of ciphertext or single ciphertext
    mapping(address => bytes) public storedCiphertext;

    event CiphertextStored(address indexed user, bytes cipher);

    /**
     * @dev User calls this with the ciphertext from off-chain encryption.
     * No key is revealed on-chain. Only the user can decrypt off-chain with their key.
     */
    function storeCiphertext(bytes calldata cipher) external {
        storedCiphertext[msg.sender] = cipher;
        emit CiphertextStored(msg.sender, cipher);
    }

    /**
     * @dev Just returns the stored ciphertext if needed
     */
    function getCiphertext(address user) external view returns (bytes memory) {
        return storedCiphertext[user];
    }
}
