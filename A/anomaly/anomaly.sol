// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract AnomalyDetector is AccessControl {
    bytes32 public constant MONITOR_ROLE = keccak256("MONITOR_ROLE");

    struct CallSnapshot {
        uint256 lastCalled;
        uint256 callCount;
        uint256 avgGas;
        uint8 anomalyScore;
    }

    mapping(bytes4 => mapping(address => CallSnapshot)) public callHistory;
    uint256 public timeWindow = 60; // seconds
    uint256 public gasThreshold = 300_000;
    uint8 public anomalyThreshold = 75;

    event AnomalyDetected(address indexed user, bytes4 indexed selector, string reason, uint8 score);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(MONITOR_ROLE, msg.sender);
    }

    /// @notice Log contract activity and auto-detect anomalies
    function logBehavior(address user, bytes4 selector, uint256 gasUsed) external onlyRole(MONITOR_ROLE) {
        CallSnapshot storage snap = callHistory[selector][user];
        uint256 nowTime = block.timestamp;

        // Update moving averages
        snap.callCount += 1;
        snap.avgGas = (snap.avgGas * (snap.callCount - 1) + gasUsed) / snap.callCount;

        // Detect anomalies
        if (gasUsed > gasThreshold) {
            snap.anomalyScore += 20;
            emit AnomalyDetected(user, selector, "High gas usage", snap.anomalyScore);
        }

        if (nowTime - snap.lastCalled <= timeWindow) {
            snap.anomalyScore += 30;
            emit AnomalyDetected(user, selector, "High call frequency", snap.anomalyScore);
        }

        if (snap.anomalyScore >= anomalyThreshold) {
            emit AnomalyDetected(user, selector, "Anomaly threshold breached", snap.anomalyScore);
        }

        snap.lastCalled = nowTime;
    }

    /// @notice Reset anomaly score (admin or auto-action)
    function resetAnomaly(address user, bytes4 selector) external onlyRole(DEFAULT_ADMIN_ROLE) {
        callHistory[selector][user].anomalyScore = 0;
    }

    /// @notice Update thresholds
    function updateConfig(uint256 _gas, uint256 _window, uint8 _threshold)
        external onlyRole(DEFAULT_ADMIN_ROLE)
    {
        gasThreshold = _gas;
        timeWindow = _window;
        anomalyThreshold = _threshold;
    }

    /// @notice View snapshot
    function getSnapshot(address user, bytes4 selector) external view returns (CallSnapshot memory) {
        return callHistory[selector][user];
    }
}
