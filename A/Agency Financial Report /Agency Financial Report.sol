// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AFRRegistry — Agency Financial Reporting with role-based submission and auditing
contract AFRRegistry {
    address public admin;

    struct AFR {
        string period;           // e.g., "Q1-2025"
        string uri;              // IPFS/Arweave pointer
        bytes32 hash;            // keccak256 of full report file
        address submitter;
        uint256 timestamp;
        bool audited;
        address auditor;
    }

    mapping(uint256 => AFR) public reports;
    uint256 public totalReports;

    mapping(address => bool) public submitters;
    mapping(address => bool) public auditors;

    event AFRSubmitted(uint256 indexed id, string period, bytes32 hash, address indexed submitter);
    event AFRAudited(uint256 indexed id, address indexed auditor);

    modifier onlySubmitter() {
        require(submitters[msg.sender], "Not a submitter");
        _;
    }

    modifier onlyAuditor() {
        require(auditors[msg.sender], "Not an auditor");
        _;
    }

    constructor() {
        admin = msg.sender;
        submitters[admin] = true;
        auditors[admin] = true;
    }

    function submitAFR(string calldata period, string calldata uri, bytes32 hash) external onlySubmitter returns (uint256) {
        uint256 id = totalReports++;
        reports[id] = AFR(period, uri, hash, msg.sender, block.timestamp, false, address(0));
        emit AFRSubmitted(id, period, hash, msg.sender);
        return id;
    }

    function auditAFR(uint256 id) external onlyAuditor {
        AFR storage afr = reports[id];
        afr.audited = true;
        afr.auditor = msg.sender;
        emit AFRAudited(id, msg.sender);
    }

    function setSubmitter(address user, bool status) external {
        require(msg.sender == admin, "Only admin");
        submitters[user] = status;
    }

    function setAuditor(address user, bool status) external {
        require(msg.sender == admin, "Only admin");
        auditors[user] = status;
    }

    function getAFR(uint256 id) external view returns (AFR memory) {
        return reports[id];
    }

    function total() external view returns (uint256) {
        return totalReports;
    }
}
