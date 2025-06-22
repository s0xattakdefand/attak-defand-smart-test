// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DueDiligenceSuite.sol
/// @notice On‑chain analogues of “Due Diligence” processes:
///   Types: Financial, Operational, Compliance, Legal  
///   AttackTypes: Misrepresentation, DataTampering, Omission, FraudulentDisclosure  
///   DefenseTypes: Verification, AuditTrail, Transparency, ThirdPartyReview  

enum DueDiligenceType            { Financial, Operational, Compliance, Legal }
enum DueDiligenceAttackType      { Misrepresentation, DataTampering, Omission, FraudulentDisclosure }
enum DueDiligenceDefenseType     { Verification, AuditTrail, Transparency, ThirdPartyReview }

error DUD__NotOwner();
error DUD__AlreadySubmitted();
error DUD__TooManyRequests();
error DUD__InvalidReport();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE REPORT SUBMISSION
///
///    • no access control, no validation → Misrepresentation
///─────────────────────────────────────────────────────────────────────────────
contract DueDiligenceVuln {
    mapping(uint256 => bytes) public reports;
    event ReportSubmitted(
        uint256 indexed id,
        DueDiligenceType       dtype,
        bytes                  data,
        DueDiligenceAttackType attack
    );

    function submitReport(uint256 id, DueDiligenceType dtype, bytes calldata data) external {
        // ❌ anyone may overwrite or submit any report
        reports[id] = data;
        emit ReportSubmitted(id, dtype, data, DueDiligenceAttackType.Misrepresentation);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB
///
///    • floods false or tampered reports
///─────────────────────────────────────────────────────────────────────────────
contract Attack_DueDiligence {
    DueDiligenceVuln public target;
    constructor(DueDiligenceVuln _t) { target = _t; }

    /// submit many bogus reports
    function floodReports(uint256[] calldata ids, DueDiligenceType dtype, bytes calldata fakeData) external {
        for (uint256 i = 0; i < ids.length; i++) {
            target.submitReport(ids[i], dtype, fakeData);
        }
    }

    /// tamper a specific report
    function tamperReport(uint256 id, DueDiligenceType dtype, bytes calldata fakeData) external {
        target.submitReport(id, dtype, fakeData);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE BASIC REPORTING (OWNER‑ONLY, ONE‑TIME)
///
///    • Defense: Verification – only owner may submit, immutable
///─────────────────────────────────────────────────────────────────────────────
contract DueDiligenceSafe {
    mapping(uint256 => bytes) public reports;
    mapping(uint256 => bool)  private _submitted;
    address public owner;

    event ReportVerified(
        uint256 indexed id,
        DueDiligenceType       dtype,
        DueDiligenceDefenseType defense
    );

    constructor() {
        owner = msg.sender;
    }

    function submitReport(uint256 id, DueDiligenceType dtype, bytes calldata data) external {
        if (msg.sender != owner)          revert DUD__NotOwner();
        if (_submitted[id])               revert DUD__AlreadySubmitted();
        if (data.length == 0)             revert DUD__InvalidReport();

        _submitted[id] = true;
        reports[id]    = data;
        emit ReportVerified(id, dtype, DueDiligenceDefenseType.Verification);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE ADVANCED REPORTING (RATE‑LIMIT & AUDIT TRAIL)
///
///    • Defense: AuditTrail – cap submissions per block + log for transparency
///─────────────────────────────────────────────────────────────────────────────
contract DueDiligenceSafeAdvanced {
    mapping(uint256 => bytes) public reports;
    mapping(uint256 => bool)  private _submitted;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public countInBlock;
    address public owner;
    uint256 public constant MAX_PER_BLOCK = 3;

    event ReportLogged(
        uint256 indexed id,
        DueDiligenceType       dtype,
        DueDiligenceDefenseType defense
    );
    event ReportAudited(
        uint256 indexed id,
        address indexed auditor,
        string                 note,
        DueDiligenceDefenseType defense
    );

    error DUD__TooManyRequests();

    constructor() {
        owner = msg.sender;
    }

    function submitReport(uint256 id, DueDiligenceType dtype, bytes calldata data) external {
        if (msg.sender != owner)          revert DUD__NotOwner();
        if (_submitted[id])               revert DUD__AlreadySubmitted();
        if (data.length == 0)             revert DUD__InvalidReport();

        // rate‑limit per block
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender]++;
        if (countInBlock[msg.sender] > MAX_PER_BLOCK) revert DUD__TooManyRequests();

        _submitted[id] = true;
        reports[id]    = data;
        emit ReportLogged(id, dtype, DueDiligenceDefenseType.AuditTrail);
    }

    /// third‑party auditor may add transparency notes
    function auditReport(uint256 id, string calldata note) external {
        // anyone can audit for transparency
        require(_submitted[id], "no such report");
        emit ReportAudited(id, msg.sender, note, DueDiligenceDefenseType.Transparency);
    }
}
