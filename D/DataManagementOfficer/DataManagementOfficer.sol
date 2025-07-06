// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/* =======================================================================
   NIST SP 800-50 r1  —  DATA-MANAGEMENT-OFFICIAL DEMO (FIXED VERSION)
   -----------------------------------------------------------------------
   · Section 1 : OpenResearchHub          (⚠️  vulnerable)
   · Section 2 : RBAC (internal _grant)   (✅  fixed)
   · Section 3 : ManagedResearchHub       (✅  compiles)
   ======================================================================= */

/* -----------------------------------------------------------------------
   SECTION 1  —  VULNERABLE “OpenResearchHub”
   -------------------------------------------------------------------- */
contract OpenResearchHub {
    struct Record {
        string  projectId;
        string  data;
        address reporter;
        uint256 timestamp;
    }

    mapping(string => Record) public projectData;

    event DataSubmitted(string indexed projectId, address indexed reporter);

    function submitData(string calldata projectId, string calldata data) external {
        projectData[projectId] = Record(projectId, data, msg.sender, block.timestamp);
        emit DataSubmitted(projectId, msg.sender);
    }

    function fetchData(string calldata projectId) external view returns (Record memory) {
        return projectData[projectId];
    }
}

/* -----------------------------------------------------------------------
   SECTION 2  —  ROLE-BASED ACCESS CONTROL  (✔ fixed visibility)
   -------------------------------------------------------------------- */
abstract contract RBAC {
    bytes32 public constant ADMIN        = keccak256("ADMIN");
    bytes32 public constant DATAMANAGER  = keccak256("DATAMANAGER");
    bytes32 public constant REPORTER     = keccak256("REPORTER");

    mapping(bytes32 => mapping(address => bool)) internal _roles;

    event RoleGranted(bytes32 indexed role, address indexed acct);
    event RoleRevoked(bytes32 indexed role, address indexed acct);

    modifier onlyRole(bytes32 r) {
        require(_roles[r][msg.sender], "RBAC: forbidden");
        _;
    }

    constructor() {
        _grant(ADMIN, msg.sender);              // deployer is first ADMIN
    }

    /* ---------- public API for ADMINS ---------- */
    function grantRole(bytes32 r, address a) external onlyRole(ADMIN) {
        _grant(r, a);
    }
    function revokeRole(bytes32 r, address a) external onlyRole(ADMIN) {
        _revoke(r, a);
    }
    function hasRole(bytes32 r, address a) public view returns (bool) {
        return _roles[r][a];
    }

    /* ---------- internal helpers (visibility fixed) ---------- */
    function _grant(bytes32 r, address a) internal {
        if (!_roles[r][a]) {
            _roles[r][a] = true;
            emit RoleGranted(r, a);
        }
    }
    function _revoke(bytes32 r, address a) internal {
        if (_roles[r][a]) {
            _roles[r][a] = false;
            emit RoleRevoked(r, a);
        }
    }
}

/* -----------------------------------------------------------------------
   SECTION 3  —  HARDENED “ManagedResearchHub”
   -------------------------------------------------------------------- */
contract ManagedResearchHub is RBAC {
    /* ---------- data structures ---------- */
    struct Project {
        string  title;
        address dataManager;
        bool    active;
    }
    struct Submission {
        string  cid;
        address reporter;
        uint256 timestamp;
    }

    /* ---------- storage ---------- */
    uint256                     public  projectCounter;
    mapping(uint256 => Project) public  projects;
    mapping(uint256 => Submission[])    private submissions;
    mapping(uint256 => mapping(address => bool)) public approvedReporter;

    /* ---------- events ---------- */
    event ProjectCreated(uint256 indexed pid, string title, address mgr);
    event ReporterApproved(uint256 indexed pid, address indexed reporter);
    event DataSubmitted(uint256 indexed pid, string cid, address indexed reporter);
    event TrainingLogged(uint256 indexed pid, string topic, uint256 when);

    /* ---------- Data-Manager actions ---------- */
    function createProject(string calldata title)
        external
        onlyRole(DATAMANAGER)
        returns (uint256 pid)
    {
        pid = ++projectCounter;
        projects[pid] = Project(title, msg.sender, true);
        emit ProjectCreated(pid, title, msg.sender);
    }

    function approveReporter(uint256 pid, address rep)
        external
        onlyProjectManager(pid)
    {
        approvedReporter[pid][rep] = true;
        _grant(REPORTER, rep);                 // ← now compiles
        emit ReporterApproved(pid, rep);
    }

    function logTraining(uint256 pid, string calldata topic)
        external
        onlyProjectManager(pid)
    {
        emit TrainingLogged(pid, topic, block.timestamp);
    }

    /* ---------- Reporter action ---------- */
    function submitData(uint256 pid, string calldata cid)
        external
        onlyRole(REPORTER)
    {
        require(projects[pid].active, "Project inactive");
        require(approvedReporter[pid][msg.sender], "Not approved");
        submissions[pid].push(Submission(cid, msg.sender, block.timestamp));
        emit DataSubmitted(pid, cid, msg.sender);
    }

    /* ---------- readers ---------- */
    function projectSubmissions(uint256 pid)
        external
        view
        returns (Submission[] memory)
    {
        return submissions[pid];
    }

    /* ---------- modifiers ---------- */
    modifier onlyProjectManager(uint256 pid) {
        require(projects[pid].dataManager == msg.sender, "Not Data Manager");
        _;
    }
}
