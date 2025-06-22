// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract MerkleFinger {
    bytes32 public root; // Merkle root of allowed identity hashes

    event FingerprintVerified(address indexed user, string label);

    constructor(bytes32 _root) {
        root = _root;
    }

    function verifyFingerprint(address user, string calldata label, bytes32[] calldata proof) external {
        bytes32 leaf = keccak256(abi.encodePacked(user, label));
        require(MerkleProof.verify(proof, root, leaf), "Invalid proof");
        emit FingerprintVerified(user, label);
    }
}
