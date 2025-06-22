// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract AnonymizedDataStore {
    bytes32 public merkleRoot;
    mapping(bytes32 => bool) public nullifiers;
    mapping(bytes32 => string) public anonymizedData;

    event AnonymizedDataSubmitted(bytes32 indexed nullifier, bytes32 indexed dataHash);

    constructor(bytes32 _merkleRoot) {
        merkleRoot = _merkleRoot;
    }

    /// @notice Submit anonymized data using Merkle proof + nullifier
    function submitAnonymizedData(
        bytes32[] calldata proof,
        bytes32 identityCommitment,
        bytes32 nullifier,
        bytes32 dataHash,
        string calldata plaintextHint // optional use-case-specific hint
    ) external {
        require(!nullifiers[nullifier], "Nullifier already used");
        require(MerkleProof.verify(proof, merkleRoot, identityCommitment), "Invalid Merkle proof");

        nullifiers[nullifier] = true;
        anonymizedData[nullifier] = plaintextHint; // or store off-chain encrypted ref

        emit AnonymizedDataSubmitted(nullifier, dataHash);
    }

    /// @notice Check if data was already submitted
    function isSubmitted(bytes32 nullifier) external view returns (bool) {
        return nullifiers[nullifier];
    }

    /// @notice Get hint or description of data
    function getHint(bytes32 nullifier) external view returns (string memory) {
        return anonymizedData[nullifier];
    }
}
