// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title GeneralAccountabilitiesOfficeAttackDefense - Full Attack and Defense Simulation for GAO in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure GAO Simulation (Vulnerable to Fake and Manipulated Audit Submissions)
contract InsecureGAO {
    mapping(uint256 => string) public auditReports;

    event AuditLogged(uint256 indexed reportId, string details);

    function submitAudit(uint256 reportId, string memory details) external {
        auditReports[reportId] = details; // BAD: Anyone can submit or overwrite audits
        emit AuditLogged(reportId, details);
    }

    function getAudit(uint256 reportId) external view returns (string memory) {
        return auditReports[reportId];
    }
}

/// @notice Secure GAO Simulation (Immutable Audits with Multi-Signature Requirements)
contract SecureGAO {
    address public immutable deployer;
    mapping(uint256 => bytes32) public auditHashes;
    mapping(uint256 => mapping(address => bool)) public auditorApprovals;
    mapping(uint256 => uint256) public approvalCounts;
    mapping(address => bool) public authorizedAuditors;
    uint256 public constant MIN_AUDITOR_APPROVALS = 2;

    event AuditProposed(uint256 indexed reportId, bytes32 auditHash);
    event AuditApproved(uint256 indexed reportId, address indexed auditor);
    event AuditFinalized(uint256 indexed reportId, bytes32 auditHash);

    constructor(address[] memory initialAuditors) {
        deployer = msg.sender;
        for (uint256 i = 0; i < initialAuditors.length; i++) {
            authorizedAuditors[initialAuditors[i]] = true;
        }
    }

    function proposeAudit(uint256 reportId, bytes32 auditHash) external {
        require(authorizedAuditors[msg.sender], "Not authorized auditor");
        require(auditHashes[reportId] == bytes32(0), "Audit already exists");
        auditHashes[reportId] = auditHash;
        auditorApprovals[reportId][msg.sender] = true;
        approvalCounts[reportId] = 1;
        emit AuditProposed(reportId, auditHash);
    }

    function approveAudit(uint256 reportId) external {
        require(authorizedAuditors[msg.sender], "Not authorized auditor");
        require(auditHashes[reportId] != bytes32(0), "No such audit proposed");
        require(!auditorApprovals[reportId][msg.sender], "Already approved");

        auditorApprovals[reportId][msg.sender] = true;
        approvalCounts[reportId] += 1;

        emit AuditApproved(reportId, msg.sender);
    }

    function finalizeAudit(uint256 reportId) external view returns (bytes32) {
        require(approvalCounts[reportId] >= MIN_AUDITOR_APPROVALS, "Not enough approvals");
        return auditHashes[reportId];
    }

    function isAuditor(address account) external view returns (bool) {
        return authorizedAuditors[account];
    }
}

/// @notice Attack contract simulating fake audit submission
contract GAOIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function fakeAudit(uint256 reportId, string memory fakeDetails) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("submitAudit(uint256,string)", reportId, fakeDetails)
        );
    }
}
