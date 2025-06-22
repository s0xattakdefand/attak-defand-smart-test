// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title LatencyAttackDefense - Full Attack and Defense Simulation for Latency Mechanisms in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Latency Handling (No Deadlines, No Freshness Checks)
contract InsecureLatency {
    uint256 public latestData;

    event DataUpdated(uint256 data);

    function updateData(uint256 data) external {
        latestData = data;
        emit DataUpdated(data);
    }
}

/// @notice Secure Latency Handling (Deadlines + Freshness Validation + Latency Logging)
contract SecureLatency {
    uint256 public latestData;
    uint256 public lastUpdateBlock;
    uint256 public lastUpdateTimestamp;
    uint256 public constant MAX_ALLOWED_DELAY = 10; // 10 blocks freshness window

    event FreshDataUpdated(uint256 data, uint256 blockNumber, uint256 timestamp);

    function updateData(uint256 data, uint256 deadlineBlock, uint256 deadlineTimestamp) external {
        require(block.number <= deadlineBlock, "Block deadline passed");
        require(block.timestamp <= deadlineTimestamp, "Timestamp deadline passed");

        latestData = data;
        lastUpdateBlock = block.number;
        lastUpdateTimestamp = block.timestamp;

        emit FreshDataUpdated(data, block.number, block.timestamp);
    }

    function isDataFresh() external view returns (bool) {
        return block.number <= lastUpdateBlock + MAX_ALLOWED_DELAY;
    }
}

/// @notice Attack contract simulating latency-based oracle or transaction desync
contract LatencyIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function submitOldData(uint256 oldData) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("updateData(uint256)", oldData)
        );
    }
}
