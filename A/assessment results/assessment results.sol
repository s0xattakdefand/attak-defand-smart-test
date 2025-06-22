// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AssessmentResultsRegistry - Secure, on-chain result storage for Web3 protocol assessments

contract AssessmentResultsRegistry {
    address public admin;

    struct Result {
        bytes32 planId;           // Linked to an assessment plan
        address target;           // Contract or protocol module evaluated
        address evaluator;        // Auditor or DAO agent
        string outcome;           // e.g., "Pass", "Fail", "Warning"
        uint8 score;              // Optional: 0–100
        string notes;             // Justification text
        uint256 timestamp;
    }

    mapping(bytes32 => Result) public results;
    bytes32[] public resultIds;

    event ResultRecorded(bytes32 indexed id, address indexed target, string outcome, uint8 score);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function recordResult(
        bytes32 planId,
        address target,
        string calldata outcome,
        uint8 score,
        string calldata notes
    ) external onlyAdmin returns (bytes32 id) {
        id = keccak256(abi.encodePacked(planId, target, outcome, block.timestamp));
        results[id] = Result({
            planId: planId,
            target: target,
            evaluator: msg.sender,
            outcome: outcome,
            score: score,
            notes: notes,
            timestamp: block.timestamp
        });
        resultIds.push(id);
        emit ResultRecorded(id, target, outcome, score);
        return id;
    }

    function getAllResults() external view returns (bytes32[] memory) {
        return resultIds;
    }

    function getResult(bytes32 id) external view returns (Result memory) {
        return results[id];
    }

    function getLatestFor(address target) external view returns (Result memory) {
        for (uint i = resultIds.length; i > 0; i--) {
            if (results[resultIds[i - 1]].target == target) {
                return results[resultIds[i - 1]];
            }
        }
        revert("No result found for target");
    }
}
