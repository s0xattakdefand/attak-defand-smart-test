// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract EmergencyManager is Ownable, Pausable {
    uint256 public lastCheckpoint;
    uint256 public checkpointBalance;
    uint256 public drainThreshold;   // e.g., 10% of balance
    uint256 public timeWindow;       // e.g., 1 hour in seconds

    event EmergencyTriggered(string reason);
    
    constructor(uint256 _drainThreshold, uint256 _timeWindow) {
        drainThreshold = _drainThreshold;
        timeWindow = _timeWindow;
        lastCheckpoint = block.timestamp;
        checkpointBalance = address(this).balance;
    }

    // Manual trigger by owner (governance authority)
    function triggerPanic() external onlyOwner {
        _pause();
        emit EmergencyTriggered("Manual panic button activated");
    }

    // Resume operations by owner after issue resolution
    function resumeOperations() external onlyOwner {
        _unpause();
    }

    // Example critical function guarded by Pausable
    function transferFunds(address payable recipient, uint256 amount) external onlyOwner whenNotPaused {
        require(address(this).balance >= amount, "Insufficient balance");
        recipient.transfer(amount);
    }

    // Automatically check for draining pattern
    function checkDrain() external {
        // If time window elapsed, reset checkpoint
        if (block.timestamp >= lastCheckpoint + timeWindow) {
            lastCheckpoint = block.timestamp;
            checkpointBalance = address(this).balance;
            return;
        }
        // If balance dropped > threshold within time window, pause
        if (checkpointBalance > 0 && address(this).balance * 100 / checkpointBalance < 100 - drainThreshold) {
            _pause();
            emit EmergencyTriggered("Auto-trigger: suspected draining attack");
        }
    }

    receive() external payable {} // Accept ETH deposits for testing
}
