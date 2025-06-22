// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract Anonymizer {
    bytes32 public merkleRoot;
    mapping(bytes32 => bool) public usedNullifiers;

    event AnonymizedAction(bytes32 indexed nullifierHash, string purpose);

    constructor(bytes32 _merkleRoot) {
        merkleRoot = _merkleRoot;
    }

    /// @notice Perform an anonymized action with proof of inclusion
    function performAnonymizedAction(
        bytes32[] calldata proof,
        bytes32 identityCommitment,
        bytes32 nullifierHash,
        string calldata purpose
    ) external {
        require(!usedNullifiers[nullifierHash], "Nullifier reused");
        require(
            MerkleProof.verify(proof, merkleRoot, identityCommitment),
            "Invalid Merkle proof"
        );

        usedNullifiers[nullifierHash] = true;
        emit AnonymizedAction(nullifierHash, purpose);
    }
}
