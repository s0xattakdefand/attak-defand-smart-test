// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RecursiveSpawnBomb {
    uint256 public count;

    constructor(uint256 depth) {
        count = depth;
        if (depth > 0) {
            new RecursiveSpawnBomb(depth - 1);
        }
    }
}
