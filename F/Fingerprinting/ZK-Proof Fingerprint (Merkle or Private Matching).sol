// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract ZKFingerprintVerifier {
    bytes32 public root; // Merkle root of allowed identity fingerprints

    event Verified(address indexed user, string label);

    constructor(bytes32 _root) {
        root = _root;
    }

    function verify(string calldata label, bytes32[] calldata proof) external {
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender, label));
        require(MerkleProof.verify(proof, root, leaf), "Invalid fingerprint");
        emit Verified(msg.sender, label);
    }
}
