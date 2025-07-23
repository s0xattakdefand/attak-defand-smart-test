// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * @title DefensiveDesign
 * @notice A smart contract for tracking vulnerabilities with defensive programming principles.
 * @dev Implements role-based access control, input validation, and reentrancy protection.
 */
contract DefensiveDesign is ReentrancyGuard {
    // Struct for stage permissions
    struct StagePermissions {
        address admin;
        mapping(address => bool) assessors;
        mapping(address => bool) reviewers;
        bool exists;
    }

    // Struct for vulnerability data
    struct Vulnerability {
        string description;
        string severity; // e.g., "Low", "Medium", "High", "Critical"
        address reportedBy;
        uint256 reportedAt;
        string status; // e.g., "Open", "In Progress", "Remediated"
        string remediation;
        address reviewedBy;
        uint256 reviewedAt;
    }

    // Storage
    mapping(string => StagePermissions) private _stages;
    mapping(bytes32 => Vulnerability[]) private _vulns;

    // Events for logging
    event StageCreated(string indexed stage, address indexed admin);
    event StageAdminTransferred(string indexed stage, address indexed oldAdmin, address indexed newAdmin);
    event AssessorGranted(string indexed stage, address indexed account);
    event AssessorRevoked(string indexed stage, address indexed account);
    event ReviewerGranted(string indexed stage, address indexed account);
    event ReviewerRevoked(string indexed stage, address indexed account);
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

    // Modifiers for access control
    modifier onlyStageAdmin(string calldata stage) {
        require(_stages[stage].exists, "Stage does not exist");
        require(_stages[stage].admin == msg.sender, "Not stage admin");
        _;
    }

    modifier onlyAssessor(string calldata stage) {
        require(_stages[stage].exists, "Stage does not exist");
        require(_stages[stage].assessors[msg.sender], "Not assessor");
        _;
    }

    modifier onlyReviewer(string calldata stage) {
        require(_stages[stage].exists, "Stage does not exist");
        require(_stages[stage].reviewers[msg.sender], "Not reviewer");
        _;
    }

    modifier onlyReader(string calldata stage) {
        require(_stages[stage].exists, "Stage does not exist");
        require(
            _stages[stage].assessors[msg.sender] || _stages[stage].reviewers[msg.sender],
            "No read access"
        );
        _;
    }

    // Internal function to generate key
    function _key(string calldata stage, string calldata assetId) private pure returns (bytes32) {
        require(bytes(stage).length > 0, "Stage cannot be empty");
        require(bytes(assetId).length > 0, "Asset ID cannot be empty");
        return keccak256(abi.encodePacked(stage, "|", assetId));
    }

    /// @notice Create a new lifecycle stage
    function createStage(string calldata stage) external nonReentrant {
        require(bytes(stage).length > 0, "Stage cannot be empty");
        StagePermissions storage p = _stages[stage];
        require(!p.exists, "Stage already exists");
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
        nonReentrant
    {
        require(newAdmin != address(0), "Invalid address");
        address oldAdmin = _stages[stage].admin;
        _stages[stage].admin = newAdmin;
        _stages[stage].assessors[newAdmin] = true;
        _stages[stage].reviewers[newAdmin] = true;
        emit StageAdminTransferred(stage, oldAdmin, newAdmin);
    }

    /// @notice Grant assessor role
    function grantAssessor(string calldata stage, address account)
        external
        onlyStageAdmin(stage)
        nonReentrant
    {
        require(account != address(0), "Invalid address");
        _stages[stage].assessors[account] = true;
        emit AssessorGranted(stage, account);
    }

    /// @notice Revoke assessor role
    function revokeAssessor(string calldata stage, address account)
        external
        onlyStageAdmin(stage)
        nonReentrant
    {
        require(account != address(0), "Invalid address");
        _stages[stage].assessors[account] = false;
        emit AssessorRevoked(stage, account);
    }

    /// @notice Grant reviewer role
    function grantReviewer(string calldata stage, address account)
        external
        onlyStageAdmin(stage)
        nonReentrant
    {
        require(account != address(0), "Invalid address");
        _stages[stage].reviewers[account] = true;
        emit ReviewerGranted(stage, account);
    }

    /// @notice Revoke reviewer role
    function revokeReviewer(string calldata stage, address account)
        external
        onlyStageAdmin(stage)
        nonReentrant
    {
        require(account != address(0), "Invalid address");
        _stages[stage].reviewers[account] = false;
        emit ReviewerRevoked(stage, account);
    }

    /// @notice Report a new vulnerability
    function reportVulnerability(
        string calldata stage,
        string calldata assetId,
        string calldata description,
        string calldata severity
    ) external onlyAssessor(stage) nonReentrant returns (uint256 index) {
        require(bytes(description).length > 0, "Description cannot be empty");
        require(bytes(severity).length > 0, "Severity cannot be empty");
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
        return index;
    }

    /// @notice Review and update a vulnerability
    function reviewVulnerability(
        string calldata stage,
        string calldata assetId,
        uint256 index,
        string calldata status,
        string calldata remediation
    ) external onlyReviewer(stage) nonReentrant {
        require(bytes(status).length > 0, "Status cannot be empty");
        bytes32 key = _key(stage, assetId);
        require(index < _vulns[key].length, "Invalid index");
        Vulnerability storage v = _vulns[key][index];
        require(v.reportedAt != 0, "Vulnerability not found");
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
    ) external onlyReader(stage) nonReentrant returns (Vulnerability memory) {
        bytes32 key = _key(stage, assetId);
        require(index < _vulns[key].length, "Invalid index");
        Vulnerability storage v = _vulns[key][index];
        require(v.reportedAt != 0, "Vulnerability not found");
        emit VulnerabilityRead(key, index, msg.sender, block.timestamp);
        return v;
    }
}