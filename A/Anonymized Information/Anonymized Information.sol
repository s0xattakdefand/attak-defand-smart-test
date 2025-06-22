// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract AnonymizedInfoHandler {
    bytes32 public merkleRoot;
    mapping(bytes32 => bool) public usedNullifiers;
    mapping(bytes32 => bytes32) public anonymizedStorage; // store infoHash per nullifier

    event InfoSubmitted(bytes32 indexed nullifier, bytes32 indexed infoHash);

    constructor(bytes32 _merkleRoot) {
        merkleRoot = _merkleRoot;
    }

    /// @notice Submit anonymized information
    function submitAnonymizedInfo(
        bytes32[] calldata proof,
        bytes32 identityCommitment,
        bytes32 nullifier,
        bytes32 infoHash
    ) external {
        require(!usedNullifiers[nullifier], "Nullifier reused");
        require(MerkleProof.verify(proof, merkleRoot, identityCommitment), "Invalid proof");

        usedNullifiers[nullifier] = true;
        anonymizedStorage[nullifier] = infoHash;

        emit InfoSubmitted(nullifier, infoHash);
    }

    /// @notice Get stored infoHash if needed for audit
    function getInfoHash(bytes32 nullifier) external view returns (bytes32) {
        return anonymizedStorage[nullifier];
    }

    /// @notice Check if a nullifier was used
    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return usedNullifiers[nullifier];
    }
}
