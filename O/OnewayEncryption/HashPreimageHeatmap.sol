// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract HashPreimageHeatmap {
    mapping(bytes32 => uint256) public hitCount;
    mapping(bytes32 => uint256) public lastUsed;

    event PreimageLogged(bytes32 indexed hash, uint256 count, uint256 time);

    function logPreimage(bytes32 hash) external {
        hitCount[hash]++;
        lastUsed[hash] = block.timestamp;
        emit PreimageLogged(hash, hitCount[hash], lastUsed[hash]);
    }

    function getHeat(bytes32 hash) external view returns (uint256 intensity, uint256 driftTime) {
        intensity = hitCount[hash];
        driftTime = block.timestamp - lastUsed[hash];
    }
}
