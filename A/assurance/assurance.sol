// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AssuranceLevelRegistry - Assigns and verifies assurance levels for smart contracts and protocols

contract AssuranceLevelRegistry {
    address public admin;

    struct Assurance {
        bytes32 id;
        address target;
        string level;         // e.g., "High", "Moderate", "Low"
        uint8 score;          // 0–100 confidence score
        string category;      // e.g., "Security", "ZK", "Governance"
        string rationale;     // Why this assurance level was given
        uint256 timestamp;
    }

    mapping(bytes32 => Assurance) public assurances;
    mapping(address => bytes32[]) public targetToAssurances;
    bytes32[] public assuranceIds;

    event AssuranceAssigned(bytes32 indexed id, address target, string level, uint8 score);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function assignAssurance(
        address target,
        string calldata level,
        uint8 score,
        string calldata category,
        string calldata rationale
    ) external onlyAdmin returns (bytes32 id) {
        id = keccak256(abi.encodePacked(target, level, block.timestamp));
        assurances[id] = Assurance({
            id: id,
            target: target,
            level: level,
            score: score,
            category: category,
            rationale: rationale,
            timestamp: block.timestamp
        });
        assuranceIds.push(id);
        targetToAssurances[target].push(id);
        emit AssuranceAssigned(id, target, level, score);
        return id;
    }

    function getAssurance(bytes32 id) external view returns (Assurance memory) {
        return assurances[id];
    }

    function getLatestAssurance(address target) external view returns (Assurance memory) {
        bytes32[] memory ids = targetToAssurances[target];
        require(ids.length > 0, "No assurances found");
        return assurances[ids[ids.length - 1]];
    }

    function getAllAssuranceIds() external view returns (bytes32[] memory) {
        return assuranceIds;
    }
}
