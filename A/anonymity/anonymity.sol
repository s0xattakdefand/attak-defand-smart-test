// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract AnonymousRelay {
    bytes32 public merkleRoot;
    mapping(bytes32 => bool) public nullifierUsed;

    event AnonymousAction(address indexed relayer, bytes32 nullifier, string action);

    constructor(bytes32 _merkleRoot) {
        merkleRoot = _merkleRoot;
    }

    /// @notice Anonymous action via Merkle proof and nullifier (prevents double-use)
    function anonymousAct(
        bytes32[] calldata merkleProof,
        bytes32 leaf,
        bytes32 nullifier,
        string calldata action
    ) external {
        require(!nullifierUsed[nullifier], "Nullifier already used");

        // Verify leaf in Merkle tree
        require(MerkleProof.verify(merkleProof, merkleRoot, leaf), "Invalid proof");

        nullifierUsed[nullifier] = true;

        emit AnonymousAction(msg.sender, nullifier, action);
    }
}
