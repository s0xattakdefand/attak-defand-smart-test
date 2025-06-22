// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * ATTACK TYPE:
 * A naive approach that stores the encryption key on-chain or does a simple XOR,
 * letting attackers easily recover plaintext. No real confidentiality.
 */
contract NaiveEncryption {
    // The contract references a 'key' stored in state
    // Attackers see it in the block explorer
    bytes32 public encryptionKey;

    event EncryptedStored(address user, bytes encrypted);

    constructor(bytes32 key) {
        encryptionKey = key; // ❌ Attack: key is fully public
    }

    /**
     * @dev A naive XOR-based encryption done on-chain,
     * attacker can just replicate the XOR with encryptionKey from the public state.
     */
    function storeEncrypted(bytes calldata data) external {
        // For demonstration, we do a trivial XOR with encryptionKey
        // in reality, this is easily reversed if the key is known
        // We'll store the resulting 'encrypted' in an event
        bytes memory result = _xorWithKey(data);
        emit EncryptedStored(msg.sender, result);
    }

    function _xorWithKey(bytes calldata input) internal view returns (bytes memory) {
        // Convert encryptionKey into a bytes array for XOR
        bytes memory out = new bytes(input.length);
        for (uint256 i = 0; i < input.length; i++) {
            out[i] = bytes1(input[i] ^ encryptionKey[i % 32]);
        }
        return out;
    }
}
