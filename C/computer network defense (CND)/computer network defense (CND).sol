// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract NetworkDefenseGuard {
    address public owner;
    mapping(address => uint256) public lastCall;
    mapping(address => bool) public flagged;
    bool public systemPaused;

    uint256 public constant MIN_CALL_INTERVAL = 30; // seconds
    uint256 public constant MAX_CALLS_PER_MIN = 5;

    mapping(address => uint256[]) internal callTimestamps;

    event SystemPaused(address by);
    event SystemResumed(address by);
    event AbuseDetected(address user, string reason);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    modifier notPaused() {
        require(!systemPaused, "System paused");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function protectedFunction() external notPaused {
        require(!flagged[msg.sender], "Flagged for abuse");

        // Rate-limit logic
        uint256[] storage timestamps = callTimestamps[msg.sender];
        timestamps.push(block.timestamp);
        if (timestamps.length > MAX_CALLS_PER_MIN) {
            if (timestamps[timestamps.length - MAX_CALLS_PER_MIN] > block.timestamp - 60) {
                flagged[msg.sender] = true;
                emit AbuseDetected(msg.sender, "Call rate exceeded");
            }
        }

        // Simulate protected logic
        lastCall[msg.sender] = block.timestamp;
    }

    function pauseSystem() external onlyOwner {
        systemPaused = true;
        emit SystemPaused(msg.sender);
    }

    function resumeSystem() external onlyOwner {
        systemPaused = false;
        emit SystemResumed(msg.sender);
    }

    function unflag(address user) external onlyOwner {
        flagged[user] = false;
    }

    function isFlagged(address user) external view returns (bool) {
        return flagged[user];
    }
}
