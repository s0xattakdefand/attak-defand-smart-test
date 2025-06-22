// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ContractThroughputCap {
    uint256 public requestsToday;
    uint256 public lastReset;
    uint256 public constant DAILY_LIMIT = 100;

    event RequestAccepted(address indexed user, uint256 timestamp);
    event DailyLimitReset(uint256 newDayStart);

    constructor() {
        lastReset = block.timestamp;
    }

    function recordRequest() public {
        // Reset if a new day has started
        if (block.timestamp > lastReset + 1 days) {
            requestsToday = 0;
            lastReset = block.timestamp;
            emit DailyLimitReset(lastReset);
        }

        require(requestsToday < DAILY_LIMIT, "Daily limit reached");

        requestsToday += 1;
        emit RequestAccepted(msg.sender, block.timestamp);

        // Add your logic here (e.g., mint, vote, send msg, etc.)
    }

    function getRemainingRequests() public view returns (uint256 remaining) {
        if (block.timestamp > lastReset + 1 days) {
            return DAILY_LIMIT;
        } else {
            return DAILY_LIMIT - requestsToday;
        }
    }
}
