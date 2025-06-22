// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RatePatternLogger {
    struct AccessLog {
        uint256 count;
        uint256 lastBlock;
        uint256 avgInterval;
    }

    mapping(address => AccessLog) public logs;

    function logAccess() external {
        AccessLog storage log = logs[msg.sender];
        uint256 interval = block.number - log.lastBlock;

        log.avgInterval = log.count == 0 ? 0 : (log.avgInterval + interval) / 2;
        log.lastBlock = block.number;
        log.count++;
    }

    function getProfile(address user) external view returns (AccessLog memory) {
        return logs[user];
    }
}
