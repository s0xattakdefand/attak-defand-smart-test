// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title GapAnalysisAttackDefense - Full Attack and Defense Simulation for Gap Analysis in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Gap Analysis System (Vulnerable to Baseline Drift and Metric Manipulation)
contract InsecureGapAnalysis {
    mapping(address => uint256) public reportedMetrics;
    uint256 public baseline;

    event MetricReported(address indexed reporter, uint256 value);

    constructor(uint256 initialBaseline) {
        baseline = initialBaseline;
    }

    function reportMetric(uint256 value) external {
        reportedMetrics[msg.sender] = value; // BAD: Anyone can report any value, no verification
        emit MetricReported(msg.sender, value);
    }

    function getGap(address reporter) external view returns (int256) {
        return int256(reportedMetrics[reporter]) - int256(baseline);
    }
}

/// @notice Secure Gap Analysis System (Immutable Baselines + Independent Gap Verification)
contract SecureGapAnalysis {
    address public immutable deployer;
    uint256 public immutable baselineSnapshot;
    mapping(address => uint256) public verifiedMetrics;
    mapping(address => bool) public metricSubmitted;
    mapping(address => int256) public gapSeverity;

    event MetricSubmitted(address indexed reporter, uint256 value, int256 severityGap);

    constructor(uint256 _baselineSnapshot) {
        deployer = msg.sender;
        baselineSnapshot = _baselineSnapshot;
    }

    function submitVerifiedMetric(uint256 measuredValue) external {
        require(!metricSubmitted[msg.sender], "Already submitted");

        int256 severity = int256(measuredValue) - int256(baselineSnapshot);

        verifiedMetrics[msg.sender] = measuredValue;
        metricSubmitted[msg.sender] = true;
        gapSeverity[msg.sender] = severity;

        emit MetricSubmitted(msg.sender, measuredValue, severity);
    }

    function getGapSeverity(address reporter) external view returns (int256) {
        return gapSeverity[reporter];
    }

    function isSevere(address reporter) external view returns (bool) {
        return gapSeverity[reporter] > 10 || gapSeverity[reporter] < -10;
    }
}

/// @notice Attack contract simulating false gap hiding
contract GapAnalysisIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function injectFalseMetric(uint256 fakeMetric) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("reportMetric(uint256)", fakeMetric)
        );
    }
}
