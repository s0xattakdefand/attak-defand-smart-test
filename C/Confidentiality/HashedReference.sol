// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * DEFENSE TYPE:
 * Instead of storing plaintext, store a hash of the data (and maybe a salt + user address).
 * Attackers can't easily retrieve the original content from this hash alone.
 */
contract HashedReference {
    // user => keccak256(...) of their secret
    mapping(address => bytes32) public secretHash;

    function commitSecret(bytes32 hashedSecret) external {
        // user computed hashedSecret = keccak256(abi.encodePacked(plaintext, salt, msg.sender))
        secretHash[msg.sender] = hashedSecret;
    }

    function verifySecret(string calldata plaintext, bytes32 salt) external view returns (bool) {
        // Recompute off-chain or in a read-only function
        bytes32 check = keccak256(abi.encodePacked(plaintext, salt, msg.sender));
        return check == secretHash[msg.sender];
    }
}
