// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract ALECalculator is AccessControl {
    bytes32 public constant RISK_MANAGER_ROLE = keccak256("RISK_MANAGER_ROLE");

    struct RiskFactor {
        uint256 assetValue; // Asset Value (in wei)
        uint256 exposureFactor; // in percentage (0-100%)
        uint256 annualOccurrence; // expected times per year
        uint256 ale; // Calculated ALE
        uint256 lastUpdated; // Timestamp
    }

    mapping(bytes32 => RiskFactor) public riskFactors;

    event RiskFactorUpdated(bytes32 indexed riskId, uint256 ale, uint256 timestamp);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(RISK_MANAGER_ROLE, msg.sender);
    }

    /// @notice Calculate ALE based on SLE and ARO dynamically
    function calculateALE(uint256 assetValue, uint256 exposureFactor, uint256 annualOccurrence)
        public pure returns (uint256)
    {
        require(exposureFactor <= 100, "Exposure factor must be <= 100%");
        uint256 sle = (assetValue * exposureFactor) / 100;
        return sle * annualOccurrence;
    }

    /// @notice Set or update a risk factor (restricted access)
    function setRiskFactor(bytes32 riskId, uint256 assetValue, uint256 exposureFactor, uint256 annualOccurrence)
        external onlyRole(RISK_MANAGER_ROLE)
    {
        uint256 newALE = calculateALE(assetValue, exposureFactor, annualOccurrence);
        riskFactors[riskId] = RiskFactor({
            assetValue: assetValue,
            exposureFactor: exposureFactor,
            annualOccurrence: annualOccurrence,
            ale: newALE,
            lastUpdated: block.timestamp
        });

        emit RiskFactorUpdated(riskId, newALE, block.timestamp);
    }

    /// @notice Retrieve ALE dynamically for any registered risk factor
    function getALE(bytes32 riskId) external view returns (uint256) {
        return riskFactors[riskId].ale;
    }

    /// @notice Adjust the Annual Occurrence Rate dynamically (rate-limited)
    function updateAnnualOccurrence(bytes32 riskId, uint256 newAnnualOccurrence)
        external onlyRole(RISK_MANAGER_ROLE)
    {
        RiskFactor storage rf = riskFactors[riskId];
        require(block.timestamp >= rf.lastUpdated + 1 days, "Update rate limited to once per day");

        rf.annualOccurrence = newAnnualOccurrence;
        rf.ale = calculateALE(rf.assetValue, rf.exposureFactor, newAnnualOccurrence);
        rf.lastUpdated = block.timestamp;

        emit RiskFactorUpdated(riskId, rf.ale, block.timestamp);
    }
}
