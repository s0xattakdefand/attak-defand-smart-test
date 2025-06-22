// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract UnorderedChunkStore {
    mapping(uint256 => string) public chunks;

    function storeChunk(uint256 id, string calldata data) external {
        chunks[id] = data; // Overwrites freely
    }

    function readChunk(uint256 id) external view returns (string memory) {
        return chunks[id];
    }
}
