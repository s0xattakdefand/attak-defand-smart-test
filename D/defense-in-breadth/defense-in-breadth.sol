// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title DefenseInBreadthRiskManager
 * @notice Tracks vulnerabilities across lifecycle stages (“Defense-in-Breadth”)
 *         with per-stage roles and event logging.
 * Sources:
 *   • NIST SP 800-30 Rev.1 under Defense-in-Breadth (CNSSI 4009)
 *   • NIST SP 800-39 under Defense-in-Breadth (CNSSI 4009)
 */
contract DefenseInBreadthRiskManager {
    struct StagePermissions {
        address admin;
        mapping(address => bool) assessors;
        mapping(address => bool) reviewers;
        bool exists;
    }

    struct Vulnerability {
        string description;
        string severity; // e.g. "Low", "Medium", "High", "Critical"
        address reportedBy;
        uint256 reportedAt;
        string status; // e.g. "Open", "In Progress", "Remediated"
        string remediation;
        address reviewedBy;
        uint256 reviewedAt;
    }

    mapping(string => StagePermissions) private _stages;
    mapping(bytes32 => Vulnerability[]) private _vulns;

    event StageCreated(string indexed stage, address indexed admin);
    event StageAdminTransferred(string indexed stage, address indexed oldAdmin, address indexed newAdmin);
    event AssessorGranted(string indexed stage, address indexed acct);
    event AssessorRevoked(string indexed stage, address indexed acct);
    event ReviewerGranted(string indexed stage, address indexed acct);
    event ReviewerRevoked(string indexed stage, address indexed acct);

    // key = keccak256(stage || "|" || assetId)
    event VulnerabilityReported(
        bytes32 indexed key,
        uint256 indexed vulnIndex,
        address reporter,
        uint256 timestamp,
        string severity,
        string description
    );
    event VulnerabilityReviewed(
        bytes32 indexed key,
        uint256 indexed vulnIndex,
        address reviewer,
        uint256 timestamp,
        string status,
        string remediation
    );
    event VulnerabilityRead(
        bytes32 indexed key,
        uint256 indexed vulnIndex,
        address reader,
        uint256 timestamp
    );

    modifier onlyStageAdmin(string calldata stage) {
        require(_stages[stage].exists, "Stage not found");
        require(_stages[stage].admin == msg.sender, "Not stage admin");
        _;
    }
    modifier onlyAssessor(string calldata stage) {
        require(_stages[stage].exists, "Stage not found");
        require(_stages[stage].assessors[msg.sender], "Not assessor");
        _;
    }
    modifier onlyReviewer(string calldata stage) {
        require(_stages[stage].exists, "Stage not found");
        require(_stages[stage].reviewers[msg.sender], "Not reviewer");
        _;
    }
    modifier onlyReader(string calldata stage) {
        require(_stages[stage].exists, "Stage not found");
        require(
            _stages[stage].assessors[msg.sender] ||
            _stages[stage].reviewers[msg.sender],
            "No read access"
        );
        _;
    }

    function _key(string calldata stage, string calldata assetId) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(stage, "|", assetId));
    }

    /// @notice Create a new lifecycle stage
    function createStage(string calldata stage) external {
        StagePermissions storage p = _stages[stage];
        require(!p.exists, "Stage exists");
        p.admin = msg.sender;
        p.assessors[msg.sender] = true;
        p.reviewers[msg.sender] = true;
        p.exists = true;
        emit StageCreated(stage, msg.sender);
    }

    /// @notice Transfer admin for a stage
    function transferStageAdmin(string calldata stage, address newAdmin)
        external
        onlyStageAdmin(stage)
    {
        require(newAdmin != address(0), "Zero addr");
        address old = _stages[stage].admin;
        _stages[stage].admin = newAdmin;
        _stages[stage].assessors[newAdmin] = true;
        _stages[stage].reviewers[newAdmin] = true;
        emit StageAdminTransferred(stage, old, newAdmin);
    }

    function grantAssessor(string calldata stage, address acct)
        external
        onlyStageAdmin(stage)
    {
        _stages[stage].assessors[acct] = true;
        emit AssessorGranted(stage, acct);
    }
    function revokeAssessor(string calldata stage, address acct)
        external
        onlyStageAdmin(stage)
    {
        _stages[stage].assessors[acct] = false;
        emit AssessorRevoked(stage, acct);
    }

    function grantReviewer(string calldata stage, address acct)
        external
        onlyStageAdmin(stage)
    {
        _stages[stage].reviewers[acct] = true;
        emit ReviewerGranted(stage, acct);
    }
    function revokeReviewer(string calldata stage, address acct)
        external
        onlyStageAdmin(stage)
    {
        _stages[stage].reviewers[acct] = false;
        emit ReviewerRevoked(stage, acct);
    }

    /// @notice Report a new vulnerability
    function reportVulnerability(
        string calldata stage,
        string calldata assetId,
        string calldata description,
        string calldata severity
    ) external onlyAssessor(stage) returns (uint256 index) {
        bytes32 key = _key(stage, assetId);
        Vulnerability[] storage arr = _vulns[key];
        arr.push(
            Vulnerability({
                description: description,
                severity: severity,
                reportedBy: msg.sender,
                reportedAt: block.timestamp,
                status: "Open",
                remediation: "",
                reviewedBy: address(0),
                reviewedAt: 0
            })
        );
        index = arr.length - 1;
        emit VulnerabilityReported(key, index, msg.sender, block.timestamp, severity, description);
    }

    /// @notice Review and update a vulnerability
    function reviewVulnerability(
        string calldata stage,
        string calldata assetId,
        uint256 index,
        string calldata status,
        string calldata remediation
    ) external onlyReviewer(stage) {
        bytes32 key = _key(stage, assetId);
        Vulnerability storage v = _vulns[key][index];
        require(v.reportedAt != 0, "Not found");
        v.status = status;
        v.remediation = remediation;
        v.reviewedBy = msg.sender;
        v.reviewedAt = block.timestamp;
        emit VulnerabilityReviewed(key, index, msg.sender, block.timestamp, status, remediation);
    }

    /// @notice Read a vulnerability record (with audit log)
    function readVulnerability(
        string calldata stage,
        string calldata assetId,
        uint256 index
    ) external onlyReader(stage) returns (Vulnerability memory) {
        bytes32 key = _key(stage, assetId);
        Vulnerability storage v = _vulns[key][index];
        require(v.reportedAt != 0, "Not found");
        emit VulnerabilityRead(key, index, msg.sender, block.timestamp);
        return v;
    }
}