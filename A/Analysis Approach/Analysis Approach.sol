// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract AnalysisApproachRegistry is AccessControl {
    bytes32 public constant ANALYST_ROLE = keccak256("ANALYST_ROLE");

    enum ApproachType {
        STATIC,
        DYNAMIC,
        FORMAL,
        SYMBOLIC,
        BEHAVIORAL,
        FUZZY
    }

    struct AnalysisEntry {
        ApproachType approach;
        bytes4 selector;
        uint8 riskScore; // 0–100
        string notes;
        uint256 timestamp;
    }

    mapping(bytes4 => AnalysisEntry[]) public analysisBySelector;

    event AnalysisLogged(bytes4 indexed selector, ApproachType indexed approach, uint8 riskScore, string notes);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ANALYST_ROLE, msg.sender);
    }

    /// @notice Log analysis using a defined approach
    function logAnalysis(
        bytes4 selector,
        ApproachType approach,
        uint8 riskScore,
        string calldata notes
    ) external onlyRole(ANALYST_ROLE) {
        require(riskScore <= 100, "Risk score out of bounds");

        analysisBySelector[selector].push(AnalysisEntry({
            approach: approach,
            selector: selector,
            riskScore: riskScore,
            notes: notes,
            timestamp: block.timestamp
        }));

        emit AnalysisLogged(selector, approach, riskScore, notes);
    }

    /// @notice Retrieve all analysis entries for a function selector
    function getAnalysis(bytes4 selector) external view returns (AnalysisEntry[] memory) {
        return analysisBySelector[selector];
    }

    /// @notice Get the highest risk score for a selector
    function getMaxRisk(bytes4 selector) external view returns (uint8 maxRisk) {
        AnalysisEntry[] memory entries = analysisBySelector[selector];
        for (uint256 i = 0; i < entries.length; i++) {
            if (entries[i].riskScore > maxRisk) {
                maxRisk = entries[i].riskScore;
            }
        }
    }
}
