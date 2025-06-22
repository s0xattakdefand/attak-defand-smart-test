// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AssessmentFindingsRegistry - Logs audit/evaluation findings with severity and mitigation tracking

contract AssessmentFindingsRegistry {
    address public admin;

    enum Severity { Info, Low, Medium, High, Critical }

    struct Finding {
        bytes32 findingId;
        bytes32 resultId;         // Link to assessment result
        address target;
        Severity severity;
        string title;
        string description;
        string recommendation;
        bool mitigated;
        uint256 timestamp;
    }

    mapping(bytes32 => Finding) public findings;
    bytes32[] public findingIds;

    event FindingLogged(bytes32 indexed findingId, bytes32 indexed resultId, Severity severity);
    event FindingMitigated(bytes32 indexed findingId);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function logFinding(
        bytes32 resultId,
        address target,
        Severity severity,
        string calldata title,
        string calldata description,
        string calldata recommendation
    ) external onlyAdmin returns (bytes32 findingId) {
        findingId = keccak256(abi.encodePacked(resultId, title, block.timestamp));
        findings[findingId] = Finding({
            findingId: findingId,
            resultId: resultId,
            target: target,
            severity: severity,
            title: title,
            description: description,
            recommendation: recommendation,
            mitigated: false,
            timestamp: block.timestamp
        });
        findingIds.push(findingId);
        emit FindingLogged(findingId, resultId, severity);
        return findingId;
    }

    function markMitigated(bytes32 findingId) external onlyAdmin {
        require(findings[findingId].timestamp != 0, "Finding not found");
        findings[findingId].mitigated = true;
        emit FindingMitigated(findingId);
    }

    function getAllFindings() external view returns (bytes32[] memory) {
        return findingIds;
    }

    function getFinding(bytes32 findingId) external view returns (Finding memory) {
        return findings[findingId];
    }

    function getFindingsForResult(bytes32 resultId) external view returns (Finding[] memory) {
        uint256 count = 0;
        for (uint i = 0; i < findingIds.length; i++) {
            if (findings[findingIds[i]].resultId == resultId) {
                count++;
            }
        }
        Finding[] memory resultFindings = new Finding[](count);
        uint256 index = 0;
        for (uint i = 0; i < findingIds.length; i++) {
            if (findings[findingIds[i]].resultId == resultId) {
                resultFindings[index++] = findings[findingIds[i]];
            }
        }
        return resultFindings;
    }
}
