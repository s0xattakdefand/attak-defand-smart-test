// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * DEFENSE TYPE:
 * Rather than storing a plaintext secret or key, 
 * we store only a hashed reference (like a commit).
 * Real usage of the secret or key is done off-chain or only revealed selectively via reveal step.
 */
contract HashedSecretReference {
    bytes32 public hashedSecret; // only the hash of the secret

    constructor(bytes32 _hash) {
        hashedSecret = _hash;
    }

    function checkSecret(string calldata attempt, bytes32 salt) external view returns (bool) {
        // Off-chain you do: hash = keccak256(abi.encodePacked(attempt, salt))
        // Then compare
        bytes32 check = keccak256(abi.encodePacked(attempt, salt));
        return (check == hashedSecret);
    }
}
