// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AdverseConsequenceLogger — Forensics + Impact Tracker
contract AdverseConsequenceLogger {
    address public admin;

    enum ImpactType { FUND_LOSS, ACCESS_BREACH, SYSTEM_PAUSE, GOVERNANCE_HIJACK, UNDEFINED }

    struct Consequence {
        address attacker;
        ImpactType impact;
        string description;
        uint256 timestamp;
    }

    Consequence[] public consequences;

    event AdverseConsequenceLogged(
        uint256 indexed id,
        address indexed attacker,
        ImpactType impact,
        string description
    );

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function logConsequence(address attacker, ImpactType impact, string calldata description) external onlyAdmin {
        consequences.push(Consequence(attacker, impact, description, block.timestamp));
        emit AdverseConsequenceLogged(consequences.length - 1, attacker, impact, description);
    }

    function getConsequence(uint256 id) external view returns (Consequence memory) {
        return consequences[id];
    }

    function totalLogged() external view returns (uint256) {
        return consequences.length;
    }
}
