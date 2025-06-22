// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract AllanDeviationTracker {
    uint256[] public timestamps;
    uint256 public windowSize = 10;

    event TimestampLogged(uint256 indexed time);
    event DriftAlert(uint256 allanDeviation);

    /// @notice Record current block timestamp
    function logTimestamp() external {
        timestamps.push(block.timestamp);
        emit TimestampLogged(block.timestamp);

        if (timestamps.length > windowSize) {
            for (uint i = 0; i < timestamps.length - windowSize; i++) {
                timestamps[i] = timestamps[i + 1];
            }
            timestamps.pop();

            uint256 deviation = computeAllanDeviation();
            if (deviation > 30) { // example: 30 seconds drift threshold
                emit DriftAlert(deviation);
            }
        }
    }

    /// @notice Approximate Allan deviation from logged timestamps
    function computeAllanDeviation() public view returns (uint256) {
        if (timestamps.length < 3) return 0;

        uint256 sumSq = 0;
        uint256 count = timestamps.length - 2;

        for (uint256 i = 0; i < count; i++) {
            uint256 tau1 = timestamps[i + 1] - timestamps[i];
            uint256 tau2 = timestamps[i + 2] - timestamps[i + 1];
            uint256 diff = int256(tau2) > int256(tau1) ? tau2 - tau1 : tau1 - tau2;
            sumSq += diff * diff;
        }

        return sqrt(sumSq / count);
    }

    /// @notice Integer square root
    function sqrt(uint y) internal pure returns (uint z) {
        if (y > 3) {
            z = y;
            uint x = y / 2 + 1;
            while (x < z) {
                z = x;
                x = (y / x + x) / 2;
            }
        } else if (y != 0) {
            z = 1;
        }
    }

    function getTimestamps() external view returns (uint256[] memory) {
        return timestamps;
    }
}
