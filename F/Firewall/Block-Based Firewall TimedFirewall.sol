// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TimedFirewall {
    uint256 public startBlock;
    uint256 public endBlock;
    uint256 public sensitiveData;

    constructor(uint256 _start, uint256 _end) {
        require(_end > _start, "Invalid block range");
        startBlock = _start;
        endBlock = _end;
    }

    modifier withinAllowedTime() {
        require(block.number >= startBlock && block.number <= endBlock, "Outside firewall window");
        _;
    }

    function updateData(uint256 _val) external withinAllowedTime {
        sensitiveData = _val;
    }
}
