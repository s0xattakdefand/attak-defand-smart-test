// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract MerkleLookupResolver {
    bytes32 public root;

    constructor(bytes32 _root) {
        root = _root;
    }

    function resolve(string calldata name, address user, bytes32[] calldata proof) external view returns (bool) {
        bytes32 leaf = keccak256(abi.encodePacked(name, user));
        return MerkleProof.verify(proof, root, leaf);
    }
}
