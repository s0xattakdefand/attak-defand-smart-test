// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

/**
 * This Registry ensures only plugins with valid hashes (pre-approved) are added.
 */

contract PluginRegistry {
    bytes32 public root; // Merkle root of approved plugin addresses

    mapping(address => bool) public activated;

    constructor(bytes32 _root) {
        root = _root;
    }

    function activatePlugin(address plugin, bytes32[] calldata proof) external {
        bytes32 leaf = keccak256(abi.encodePacked(plugin));
        require(MerkleProof.verify(proof, root, leaf), "Invalid plugin");
        activated[plugin] = true;
    }
}
