// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AWARELogger — Adaptive Risk Enumeration for decentralized systems
contract AWARELogger {
    address public admin;

    enum RiskType { UNKNOWN, ENTROPY_DRIFT, FALLBACK_ATTACK, SELECTOR_SPOOF, GAS_GRIEF, ZK_PROOF_SPOOF }

    struct RiskEvent {
        address actor;
        RiskType kind;
        uint256 score;      // Risk score (0–100+)
        string description;
        uint256 timestamp;
    }

    RiskEvent[] public risks;

    event RiskDetected(address indexed actor, RiskType kind, uint256 score, string description);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Admin only");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function logRisk(address actor, RiskType kind, uint256 score, string calldata description) external onlyAdmin {
        risks.push(RiskEvent(actor, kind, score, description, block.timestamp));
        emit RiskDetected(actor, kind, score, description);
    }

    function getRisk(uint256 index) external view returns (RiskEvent memory) {
        return risks[index];
    }

    function totalRisks() external view returns (uint256) {
        return risks.length;
    }
}
