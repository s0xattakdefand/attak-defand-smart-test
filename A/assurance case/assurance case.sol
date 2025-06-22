// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AssuranceCaseRegistry - Registers structured safety/security arguments for Web3 protocols

contract AssuranceCaseRegistry {
    address public admin;

    struct AssuranceCase {
        bytes32 id;
        string title;
        string goal;              // e.g., "Bridge transaction integrity"
        string summary;           // Human-readable argument summary
        bytes32[] assumptions;    // Assumption IDs (from AssumptionRegistry)
        bytes32[] evidenceIds;    // Links to Findings, Results, Plans, etc.
        address subject;          // Contract or module being assured
        uint256 createdAt;
    }

    mapping(bytes32 => AssuranceCase) public assuranceCases;
    bytes32[] public caseIds;

    event AssuranceCaseRegistered(bytes32 indexed id, string title, address subject);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerAssuranceCase(
        string calldata title,
        string calldata goal,
        string calldata summary,
        bytes32[] calldata assumptions,
        bytes32[] calldata evidenceIds,
        address subject
    ) external onlyAdmin returns (bytes32 id) {
        id = keccak256(abi.encodePacked(title, subject, block.timestamp));
        assuranceCases[id] = AssuranceCase({
            id: id,
            title: title,
            goal: goal,
            summary: summary,
            assumptions: assumptions,
            evidenceIds: evidenceIds,
            subject: subject,
            createdAt: block.timestamp
        });
        caseIds.push(id);
        emit AssuranceCaseRegistered(id, title, subject);
        return id;
    }

    function getAssuranceCase(bytes32 id) external view returns (AssuranceCase memory) {
        return assuranceCases[id];
    }

    function getAllCaseIds() external view returns (bytes32[] memory) {
        return caseIds;
    }
}
