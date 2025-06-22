// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DepthGuardedExecutor {
    uint256 public maxDepth = 10;

    event Executed(uint256 depth);

    function safeExecute(uint256 depth) external {
        require(depth <= maxDepth, "Exceeded safe depth");
        for (uint256 i = 0; i < depth; i++) {
            emit Executed(i);
        }
    }
}
