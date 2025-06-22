// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AFRRegistry — Agency Financial Report Log for DAOs & onchain treasuries
contract AFRRegistry {
    address public controller;

    struct AFR {
        string quarter;         // e.g., "Q1-2025"
        string ipfsURI;         // Link to the report PDF or JSON
        bytes32 hash;           // Hash of the full report content
        address issuer;
        uint256 timestamp;
        bool audited;
    }

    AFR[] public reports;

    event AFRSubmitted(uint256 indexed id, string quarter, address issuer);
    event AFRAudited(uint256 indexed id, address auditor);

    modifier onlyController() {
        require(msg.sender == controller, "Only controller can manage AFR");
        _;
    }

    constructor() {
        controller = msg.sender;
    }

    function submitAFR(
        string calldata quarter,
        string calldata ipfsURI,
        bytes32 contentHash
    ) external returns (uint256) {
        reports.push(AFR(quarter, ipfsURI, contentHash, msg.sender, block.timestamp, false));
        uint256 id = reports.length - 1;
        emit AFRSubmitted(id, quarter, msg.sender);
        return id;
    }

    function auditAFR(uint256 id) external onlyController {
        reports[id].audited = true;
        emit AFRAudited(id, msg.sender);
    }

    function getAFR(uint256 id) external view returns (AFR memory) {
        return reports[id];
    }

    function totalAFRs() external view returns (uint256) {
        return reports.length;
    }
}
