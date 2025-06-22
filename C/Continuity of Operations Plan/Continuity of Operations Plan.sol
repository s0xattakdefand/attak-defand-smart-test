// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ContinuityOfOperationsPlan {
    address public owner;
    bool public emergencyMode;

    struct SystemState {
        uint256 criticalData;
        uint256 lastUpdated;
    }

    SystemState public currentState;
    SystemState private backupState;

    event StateUpdated(uint256 data, uint256 timestamp);
    event EmergencyActivated();
    event EmergencyDeactivated();
    event StateRecovered(uint256 recoveredData, uint256 recoveredTimestamp);

    modifier onlyOwner() {
        require(msg.sender == owner, "Unauthorized: owner only");
        _;
    }

    modifier notInEmergency() {
        require(!emergencyMode, "Emergency mode active");
        _;
    }

    constructor() {
        owner = msg.sender;
        emergencyMode = false;
        currentState = SystemState(0, block.timestamp);
    }

    // Regular operational function with automatic snapshot
    function updateCriticalData(uint256 newData) external notInEmergency {
        snapshotState();
        currentState.criticalData = newData;
        currentState.lastUpdated = block.timestamp;

        emit StateUpdated(newData, block.timestamp);
    }

    // Activate emergency (Circuit Breaker)
    function activateEmergency() external onlyOwner {
        emergencyMode = true;
        emit EmergencyActivated();
    }

    // Deactivate emergency mode
    function deactivateEmergency() external onlyOwner {
        emergencyMode = false;
        emit EmergencyDeactivated();
    }

    // Snapshot current state
    function snapshotState() internal {
        backupState = currentState;
    }

    // Restore last known good state
    function recoverState() external onlyOwner {
        require(emergencyMode, "Activate emergency first");
        currentState = backupState;
        emit StateRecovered(currentState.criticalData, currentState.lastUpdated);
    }

    // View backup state (for transparency)
    function viewBackupState() external view returns (uint256, uint256) {
        return (backupState.criticalData, backupState.lastUpdated);
    }
}
