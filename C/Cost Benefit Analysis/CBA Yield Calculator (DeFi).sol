// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CBAYieldEvaluator {
    function worthHarvest(uint256 gasCost, uint256 yieldEarned) public pure returns (bool) {
        return yieldEarned > gasCost;
    }

    function yieldDelta(uint256 gasCost, uint256 yieldEarned) public pure returns (int256) {
        return int256(yieldEarned) - int256(gasCost);
    }
}
