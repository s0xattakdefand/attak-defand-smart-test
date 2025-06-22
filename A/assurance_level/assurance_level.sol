// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AssuranceLevelManager - Tracks assurance levels of contracts, identities, or proofs

contract AssuranceLevelManager {
    address public admin;

    enum Level { Unverified, Low, Moderate, High, Formal, ZKAttested }

    struct Assurance {
        Level level;
        string category;     // e.g., "Security", "Governance", "ZK", "Bridge"
        string rationale;    // e.g., "Audited by XYZ", "ZK proof verified"
        uint256 timestamp;
    }

    mapping(address => Assurance) public assurances;
    address[] public targets;

    event AssuranceAssigned(address indexed target, Level level, string category);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Admin only");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function setAssurance(
        address target,
        Level level,
        string calldata category,
        string calldata rationale
    ) external onlyAdmin {
        assurances[target] = Assurance(level, category, rationale, block.timestamp);
        targets.push(target);
        emit AssuranceAssigned(target, level, category);
    }

    function getAssuranceLevel(address target) external view returns (Level) {
        return assurances[target].level;
    }

    function getAllTargets() external view returns (address[] memory) {
        return targets;
    }
}
