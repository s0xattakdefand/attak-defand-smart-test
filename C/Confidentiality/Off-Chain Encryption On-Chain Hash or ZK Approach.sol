// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Defense scenario:
 * We store only a hashed or zero-knowledge commitment 
 * so the underlying secret remains off-chain or encrypted.
 */
contract CommitmentStorage {
    // user => hash of their secret
    // or user => zero-knowledge commitment
    mapping(address => bytes32) public commitments;

    event SecretCommitted(address indexed user, bytes32 commitment);

    /**
     * @dev User commits the hash of their secret (secret + salt).
     */
    function commitSecret(bytes32 commitment) external {
        commitments[msg.sender] = commitment;
        emit SecretCommitted(msg.sender, commitment);
    }

    /**
     * @dev (Optional) verify the secret off-chain or reveal in a commit-reveal scheme.
     */
    function reveal(
        string calldata secret,
        bytes32 salt
    ) external view returns (bool) {
        // This is a read-only function to demonstrate matching
        bytes32 check = keccak256(abi.encodePacked(secret, salt, msg.sender));
        return (check == commitments[msg.sender]);
    }
}
