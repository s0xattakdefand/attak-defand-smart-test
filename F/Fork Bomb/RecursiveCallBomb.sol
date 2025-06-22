// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RecursiveCallBomb {
    uint256 public bombCount;

    function bomb(uint256 depth) external {
        bombCount++;
        if (depth > 0) {
            this.bomb(depth - 1);
        }
    }
}
