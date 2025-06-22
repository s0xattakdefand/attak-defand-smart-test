// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// ATPNThreatRelay — Advanced Threat Protection Network: Telemetry + Mitigation
contract ATPNThreatRelay {
    address public controller;
    bool public autoMitigationEnabled;

    struct ThreatLog {
        address source;
        bytes4 selector;
        uint256 entropyScore;
        uint256 timestamp;
        string threatType;
    }

    ThreatLog[] public logs;

    event ThreatDetected(address indexed source, bytes4 selector, string threatType, uint256 entropyScore);
    event AutoMitigationTriggered(address indexed source);
    event SystemStatusUpdated(bool enabled);

    modifier onlyController() {
        require(msg.sender == controller, "Not controller");
        _;
    }

    constructor() {
        controller = msg.sender;
        autoMitigationEnabled = true;
    }

    function reportThreat(
        address source,
        bytes4 selector,
        uint256 entropyScore,
        string calldata threatType
    ) external {
        logs.push(ThreatLog(source, selector, entropyScore, block.timestamp, threatType));
        emit ThreatDetected(source, selector, threatType, entropyScore);

        if (autoMitigationEnabled && entropyScore > 80) {
            // e.g., pause source, trigger circuit breaker (externalized)
            emit AutoMitigationTriggered(source);
        }
    }

    function toggleMitigation(bool enabled) external onlyController {
        autoMitigationEnabled = enabled;
        emit SystemStatusUpdated(enabled);
    }

    function getThreatLog(uint256 index) external view returns (ThreatLog memory) {
        return logs[index];
    }

    function totalThreats() external view returns (uint256) {
        return logs.length;
    }
}
