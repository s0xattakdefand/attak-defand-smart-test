// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract AnonymousIdentifierRegistry {
    bytes32 public merkleRoot;
    mapping(bytes32 => bool) public usedNullifiers;
    mapping(bytes32 => bool) public registeredIdentifiers;

    event AnonymousIdentifierUsed(bytes32 indexed nullifier, string action);

    constructor(bytes32 _merkleRoot) {
        merkleRoot = _merkleRoot;
    }

    /// @notice Register an anonymous identifier (one-time)
    function useAnonymousIdentifier(
        bytes32[] calldata merkleProof,
        bytes32 identityCommitment,
        bytes32 nullifier,
        string calldata action
    ) external {
        require(!usedNullifiers[nullifier], "Nullifier already used");
        require(MerkleProof.verify(merkleProof, merkleRoot, identityCommitment), "Invalid Merkle proof");

        usedNullifiers[nullifier] = true;
        registeredIdentifiers[identityCommitment] = true;

        emit AnonymousIdentifierUsed(nullifier, action);
    }

    /// @notice Check if a nullifier was used
    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return usedNullifiers[nullifier];
    }

    /// @notice Check if an identifier is registered
    function isIdentifierRegistered(bytes32 id) external view returns (bool) {
        return registeredIdentifiers[id];
    }
}
