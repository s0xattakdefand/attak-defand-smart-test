// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract MerkleFragmentStorage {
    bytes32 public root;
    mapping(uint256 => bool) public used;

    constructor(bytes32 _root) {
        root = _root;
    }

    function submitFragment(
        uint256 offset,
        string calldata data,
        bytes32[] calldata proof
    ) external returns (bool) {
        bytes32 leaf = keccak256(abi.encodePacked(offset, data));
        require(!used[offset], "Already used");
        require(MerkleProof.verify(proof, root, leaf), "Invalid fragment");
        used[offset] = true;
        return true;
    }
}
