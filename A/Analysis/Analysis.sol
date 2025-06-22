// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract RiskAnalysisLogger is AccessControl {
    bytes32 public constant ANALYST_ROLE = keccak256("ANALYST_ROLE");

    struct AnalysisLog {
        uint256 timestamp;
        address caller;
        bytes4 selector;
        uint256 gasUsed;
        uint8 riskScore; // 0–100
    }

    uint8 public constant RISK_THRESHOLD = 80;
    mapping(bytes32 => AnalysisLog[]) public analysisHistory;
    mapping(address => uint8) public lastRiskScore;

    event FunctionAnalyzed(address indexed caller, bytes4 selector, uint8 riskScore, uint256 gasUsed);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ANALYST_ROLE, msg.sender);
    }

    /// @notice Log analysis of a function call
    function logAnalysis(address caller, bytes4 selector, uint256 gasUsed, uint8 riskScore)
        external onlyRole(ANALYST_ROLE)
    {
        require(riskScore <= 100, "Invalid risk score");
        bytes32 logKey = keccak256(abi.encodePacked(selector, caller));

        AnalysisLog memory log = AnalysisLog({
            timestamp: block.timestamp,
            caller: caller,
            selector: selector,
            gasUsed: gasUsed,
            riskScore: riskScore
        });

        analysisHistory[logKey].push(log);
        lastRiskScore[caller] = riskScore;

        emit FunctionAnalyzed(caller, selector, riskScore, gasUsed);
    }

    /// @notice Block risky operations based on past risk score
    function isAllowed(address user) public view returns (bool) {
        return lastRiskScore[user] < RISK_THRESHOLD;
    }

    /// @notice Fetch recent logs
    function getLastLogs(address user, bytes4 selector) external view returns (AnalysisLog[] memory) {
        return analysisHistory[keccak256(abi.encodePacked(selector, user))];
    }
}
