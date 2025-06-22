// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TimeFilter {
    uint256 public startBlock;
    uint256 public endBlock;

    constructor(uint256 _start, uint256 _end) {
        require(_end > _start, "Invalid block range");
        startBlock = _start;
        endBlock = _end;
    }

    function timedAction() external view returns (string memory) {
        require(block.number >= startBlock, "Too early");
        require(block.number <= endBlock, "Too late");
        return "Executed within filter";
    }
}
