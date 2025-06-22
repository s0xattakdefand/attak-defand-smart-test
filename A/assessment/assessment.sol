// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AssessmentRegistry - On-chain evaluation system for protocols and smart contracts

contract AssessmentRegistry {
    address public admin;

    struct Assessment {
        address target;            // Contract or protocol address
        string category;           // e.g., "Security", "Performance"
        string tag;                // e.g., "Stable", "Critical", "Low Risk"
        uint8 score;               // 0–100 or scaled
        string summary;            // Optional report summary
        uint256 timestamp;
    }

    mapping(bytes32 => Assessment) public assessments;
    bytes32[] public assessmentIds;

    event AssessmentRecorded(
        bytes32 indexed id,
        address indexed target,
        string category,
        uint8 score,
        string tag
    );

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function recordAssessment(
        address target,
        string calldata category,
        string calldata tag,
        uint8 score,
        string calldata summary
    ) external onlyAdmin returns (bytes32 id) {
        id = keccak256(abi.encodePacked(target, category, tag, block.timestamp));
        assessments[id] = Assessment({
            target: target,
            category: category,
            tag: tag,
            score: score,
            summary: summary,
            timestamp: block.timestamp
        });
        assessmentIds.push(id);
        emit AssessmentRecorded(id, target, category, score, tag);
        return id;
    }

    function getAllAssessments() external view returns (bytes32[] memory) {
        return assessmentIds;
    }

    function getLatestFor(address target, string calldata category) external view returns (Assessment memory) {
        for (uint i = assessmentIds.length; i > 0; i--) {
            bytes32 id = assessmentIds[i - 1];
            if (
                assessments[id].target == target &&
                keccak256(bytes(assessments[id].category)) == keccak256(bytes(category))
            ) {
                return assessments[id];
            }
        }
        revert("No assessment found");
    }
}
