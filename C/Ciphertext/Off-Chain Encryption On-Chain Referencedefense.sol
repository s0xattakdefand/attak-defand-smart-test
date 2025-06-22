// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Secure approach: store only the ciphertext (or its hash).
 * Real encryption is done off-chain. The key remains off-chain too.
 */
contract SecureCiphertextReference {
    bytes32 public cipherHash; // reference to the actual ciphertext
    address public admin;

    event CipherStored(bytes32 indexed newHash);

    constructor(address _admin) {
        admin = _admin;
    }

    function storeCiphertext(bytes memory ciphertext) external {
        require(msg.sender == admin, "Not authorized");
        // Keep only a hash for minimal storage
        cipherHash = keccak256(ciphertext);
        emit CipherStored(cipherHash);
    }

    function verifyCipher(bytes memory ciphertext) external view returns (bool) {
        return (keccak256(ciphertext) == cipherHash);
    }
}
