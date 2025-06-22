// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract MerkleValidatedFragments {
    bytes32 public merkleRoot;
    mapping(uint256 => bool) public verifiedOffsets;

    constructor(bytes32 _root) {
        merkleRoot = _root;
    }

    function submitFragment(
        uint256 offset,
        string calldata data,
        bytes32[] calldata proof
    ) external returns (bool) {
        bytes32 leaf = keccak256(abi.encodePacked(offset, data));
        require(!verifiedOffsets[offset], "Already submitted");
        require(MerkleProof.verify(proof, merkleRoot, leaf), "Invalid proof");

        verifiedOffsets[offset] = true;
        return true;
    }
}
