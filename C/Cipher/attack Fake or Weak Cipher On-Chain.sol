// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * A naive 'encryption' approach that just XORs data with a key on-chain.
 * Attackers can easily recover the key & decrypt all data (XOR is insecure).
 */
contract NaiveCipher {
    // anyone can store an XOR-based 'encrypted' message
    mapping(address => bytes) public storedCipher;

    function storeXORCipher(bytes calldata plaintext, bytes calldata key) external {
        // ❌ XOR 'encryption' on-chain is easily reversed
        require(plaintext.length == key.length, "Len mismatch");
        bytes memory output = new bytes(plaintext.length);

        for (uint i = 0; i < plaintext.length; i++) {
            output[i] = bytes1(uint8(plaintext[i]) ^ uint8(key[i]));
        }
        storedCipher[msg.sender] = output;
    }
}
