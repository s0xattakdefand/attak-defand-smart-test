// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Actual Residual Risk Tracker for Web3 Security

contract ResidualRiskManager {
    address public admin;
    uint256 public inherentRisk;        // Raw risk score before controls
    uint256 public mitigationScore;     // Cumulative effect of controls
    uint256 public residualRisk;        // Remaining risk after all controls
    uint256 public latentExposure;      // Unknown/uncontrollable risks

    event RiskUpdated(uint256 inherent, uint256 mitigation, uint256 latent, uint256 residual);
    event ControlApplied(string label, uint256 scoreImpact);
    event ExposureLogged(string detail, uint256 riskAdd);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Admin only");
        _;
    }

    constructor(uint256 _inherentRisk) {
        admin = msg.sender;
        inherentRisk = _inherentRisk;
        residualRisk = _inherentRisk;
    }

    // Apply mitigation (e.g., reentrancy guard, signature validation)
    function applyControl(string calldata label, uint256 scoreImpact) external onlyAdmin {
        mitigationScore += scoreImpact;
        _recalculate();
        emit ControlApplied(label, scoreImpact);
    }

    // Log latent risk (e.g., unfixable edge case, unknown oracle drift)
    function addLatentExposure(string calldata detail, uint256 riskAdd) external onlyAdmin {
        latentExposure += riskAdd;
        _recalculate();
        emit ExposureLogged(detail, riskAdd);
    }

    function _recalculate() internal {
        residualRisk = inherentRisk - mitigationScore + latentExposure;
        emit RiskUpdated(inherentRisk, mitigationScore, latentExposure, residualRisk);
    }

    function getRiskState() external view returns (uint256 inherent, uint256 control, uint256 latent, uint256 residual) {
        return (inherentRisk, mitigationScore, latentExposure, residualRisk);
    }
}
