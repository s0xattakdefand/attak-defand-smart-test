pragma solidity ^0.8.21;

contract TimeWindowExecution {
    uint256 public scheduledAt;
    uint256 public tolerance = 15 seconds;

    constructor(uint256 _scheduledAt) {
        scheduledAt = _scheduledAt;
    }

    function execute() external {
        require(
            block.timestamp >= scheduledAt - tolerance &&
            block.timestamp <= scheduledAt + tolerance,
            "Not within allowed jitter window"
        );
        // Timed logic...
    }
}
