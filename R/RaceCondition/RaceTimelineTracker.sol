// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract RaceTimelineTracker {
    struct CallLog {
        address caller;
        uint256 timestamp;
        uint256 blockNumber;
    }

    mapping(bytes32 => CallLog) public calls;

    event DriftDetected(bytes32 id, uint256 drift, uint256 blockLag);

    function logCall(bytes32 id) external {
        CallLog storage log = calls[id];
        if (log.blockNumber != 0) {
            uint256 drift = block.timestamp - log.timestamp;
            uint256 blockLag = block.number - log.blockNumber;
            emit DriftDetected(id, drift, blockLag);
        }

        calls[id] = CallLog(msg.sender, block.timestamp, block.number);
    }
}
