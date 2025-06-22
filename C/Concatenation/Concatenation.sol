// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract SafeConcatHasher {
    mapping(bytes32 => bool) public knownHashes;

    event UnsafeHash(bytes32 indexed hash, string inputA, string inputB);
    event SafeHash(bytes32 indexed hash, string inputA, string inputB);

    function unsafeConcatHash(string calldata a, string calldata b) external returns (bytes32 hash) {
        hash = keccak256(abi.encodePacked(a, b));
        emit UnsafeHash(hash, a, b);
        require(!knownHashes[hash], "Collision detected");
        knownHashes[hash] = true;
    }

    function safeConcatHash(string calldata a, string calldata b) external returns (bytes32 hash) {
        hash = keccak256(abi.encode(a, b)); // safer than encodePacked for dynamic types
        emit SafeHash(hash, a, b);
        require(!knownHashes[hash], "Collision detected");
        knownHashes[hash] = true;
    }

    function resetHash(bytes32 hash) external {
        knownHashes[hash] = false;
    }
}
