// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CallVolumeThrottling {
    uint256 public callCount;
    uint256 public callWindowStart;
    uint256 public constant WINDOW_SIZE = 60; // 1 minute window
    uint256 public constant MAX_CALLS = 50;   // Max 50 calls per window

    event CallAccepted(address indexed caller, uint256 timestamp);

    constructor() {
        callWindowStart = block.timestamp;
    }

    function throttleControlledAction() public {
        // If current window has passed, reset
        if (block.timestamp > callWindowStart + WINDOW_SIZE) {
            callWindowStart = block.timestamp;
            callCount = 0;
        }

        require(callCount < MAX_CALLS, "Call rate exceeded in current window");

        callCount++;
        emit CallAccepted(msg.sender, block.timestamp);

        // Add your core logic here
    }

    function getThrottleStatus() public view returns (uint256 remainingCalls, uint256 timeLeft) {
        if (block.timestamp > callWindowStart + WINDOW_SIZE) {
            return (MAX_CALLS, 0);
        }
        return (MAX_CALLS - callCount, (callWindowStart + WINDOW_SIZE) - block.timestamp);
    }
}
