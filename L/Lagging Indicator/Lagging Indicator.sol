// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title LaggingIndicatorAttackDefense - Full Attack and Defense Simulation for Lagging Indicators in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Lagging Indicator (Slow, Unprotected, Easily Manipulated)
contract InsecureLaggingIndicator {
    uint256 public lastRecordedValue;
    uint256 public lastRecordedBlock;

    event IndicatorUpdated(uint256 value, uint256 blockNumber);

    function updateIndicator(uint256 observedValue) external {
        // BAD: No smoothing, no frequency control
        lastRecordedValue = observedValue;
        lastRecordedBlock = block.number;
        emit IndicatorUpdated(observedValue, block.number);
    }
}

/// @notice Secure Lagging Indicator (Moving Average + Frequent Update Control + Anomaly Logging)
contract SecureLaggingIndicator {
    uint256 public smoothedValue;
    uint256 public lastUpdateBlock;
    uint256 public constant SMOOTHING_FACTOR = 10; // Exponential moving average denominator
    uint256 public constant MIN_UPDATE_INTERVAL = 3; // Minimum blocks between updates
    uint256 public constant ANOMALY_THRESHOLD = 30; // 30% deviation threshold

    event SmoothedIndicatorUpdated(uint256 newValue, uint256 blockNumber);
    event AnomalyDetected(uint256 deviationPercent, uint256 reportedValue, uint256 smoothedValue);

    function updateIndicator(uint256 observedValue) external {
        require(block.number >= lastUpdateBlock + MIN_UPDATE_INTERVAL, "Update too frequent");

        uint256 deviationPercent = _calculateDeviationPercent(smoothedValue, observedValue);

        if (deviationPercent > ANOMALY_THRESHOLD) {
            emit AnomalyDetected(deviationPercent, observedValue, smoothedValue);
        }

        if (smoothedValue == 0) {
            smoothedValue = observedValue; // Bootstrap
        } else {
            smoothedValue = (smoothedValue * (SMOOTHING_FACTOR - 1) + observedValue) / SMOOTHING_FACTOR;
        }

        lastUpdateBlock = block.number;
        emit SmoothedIndicatorUpdated(smoothedValue, block.number);
    }

    function _calculateDeviationPercent(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 100;
        }
        uint256 diff = a > b ? a - b : b - a;
        return (diff * 100) / a;
    }
}

/// @notice Attack contract simulating fast manipulation before lagging detection
contract LaggingIndicatorIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function spamFakeData(uint256 fakeValue) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("updateIndicator(uint256)", fakeValue)
        );
    }
}
