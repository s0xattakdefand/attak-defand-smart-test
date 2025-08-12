// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title DeveloperRegistry
 * @notice On-chain registry of developers with roles, profiles, skills, project assignments,
 *         verification status, and full event logging.
 *
 * ✱ Features
 * - Register/update developer profile (name, contactURI, metadataURI)
 * - Add/remove skills (bytes32 tags) with O(1) deletion (swap & pop)
 * - Assign/unassign projects (uint256 IDs) with O(1) deletion
 * - Verify/unverify developers (e.g., KYC/HR approval)
 * - Role system: ADMIN, REVIEWER, PROJECT_MANAGER
 * - Query helpers to list skills and projects
 *
 * ⚠️ Notes
 * - This contract does not store private data; keep URIs/strings non-sensitive.
 * - Skills are bytes32 tags (e.g., keccak256("solidity"), "rust", etc.).
 */
contract DeveloperRegistry {
    // ---------- Roles ----------
    bytes32 public constant ADMIN           = keccak256("ADMIN");
    bytes32 public constant REVIEWER        = keccak256("REVIEWER");
    bytes32 public constant PROJECT_MANAGER = keccak256("PROJECT_MANAGER");

    mapping(bytes32 => mapping(address => bool)) private _roles;

    modifier onlyRole(bytes32 role) {
        require(_roles[role][msg.sender], "Access denied: missing role");
        _;
    }

    // ---------- Developer model ----------
    struct Developer {
        uint256 id;
        address account;
        string  name;          // display name
        string  contactURI;    // email, DID, etc. (URI/string)
        string  metadataURI;   // optional JSON metadata (IPFS/HTTPS)
        bool    verified;      // set by REVIEWER/ADMIN
        uint256 registeredAt;
        bool    exists;

        // Skills
        bytes32[] skills;
        mapping(bytes32 => uint256) skillIndex; // tag => index+1 (0 means not present)

        // Projects
        uint256[] projects;
        mapping(uint256 => uint256) projectIndex; // pid => index+1
    }

    uint256 public nextDeveloperId; // starts at 0, we will ++ before use so ids start at 1
    mapping(uint256 => Developer) private _developers;  // id => Developer
    mapping(address => uint256) public devIdOf;         // account => developerId (0 if none)

    // ---------- Events ----------
    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);

    event DeveloperRegistered(uint256 indexed devId, address indexed account, string name);
    event ProfileUpdated(uint256 indexed devId, string name, string contactURI, string metadataURI, address indexed by);
    event VerificationSet(uint256 indexed devId, bool verified, address indexed by);

    event SkillAdded(uint256 indexed devId, bytes32 indexed tag, address indexed by);
    event SkillRemoved(uint256 indexed devId, bytes32 indexed tag, address indexed by);

    event ProjectAssigned(uint256 indexed devId, uint256 indexed projectId, address indexed by);
    event ProjectUnassigned(uint256 indexed devId, uint256 indexed projectId, address indexed by);

    // ---------- Constructor ----------
    constructor() {
        _grantRole(ADMIN, msg.sender);
        _grantRole(REVIEWER, msg.sender);
        _grantRole(PROJECT_MANAGER, msg.sender);
    }

    // ---------- Role management ----------
    function grantRole(bytes32 role, address account) external onlyRole(ADMIN) {
        _grantRole(role, account);
    }

    function revokeRole(bytes32 role, address account) external onlyRole(ADMIN) {
        _revokeRole(role, account);
    }

    function hasRole(bytes32 role, address account) external view returns (bool) {
        return _roles[role][account];
    }

    function _grantRole(bytes32 role, address account) internal {
        if (!_roles[role][account]) {
            _roles[role][account] = true;
            emit RoleGranted(role, account);
        }
    }

    function _revokeRole(bytes32 role, address account) internal {
        if (_roles[role][account]) {
            _roles[role][account] = false;
            emit RoleRevoked(role, account);
        }
    }

    // ---------- Registration & profile ----------
    /// @notice Self-register as a developer (one profile per address)
    function register(string calldata name, string calldata contactURI, string calldata metadataURI)
        external
        returns (uint256 devId)
    {
        require(devIdOf[msg.sender] == 0, "Already registered");
        devId = ++nextDeveloperId; // ids start at 1
        Developer storage d = _developers[devId];
        d.id = devId;
        d.account = msg.sender;
        d.name = name;
        d.contactURI = contactURI;
        d.metadataURI = metadataURI;
        d.registeredAt = block.timestamp;
        d.exists = true;

        devIdOf[msg.sender] = devId;
        emit DeveloperRegistered(devId, msg.sender, name);
    }

    /// @notice Admin can register on behalf of an account (e.g., HR bootstrap)
    function adminRegister(address account, string calldata name, string calldata contactURI, string calldata metadataURI)
        external
        onlyRole(ADMIN)
        returns (uint256 devId)
    {
        require(account != address(0), "account=0");
        require(devIdOf[account] == 0, "Already registered");
        devId = ++nextDeveloperId;
        Developer storage d = _developers[devId];
        d.id = devId;
        d.account = account;
        d.name = name;
        d.contactURI = contactURI;
        d.metadataURI = metadataURI;
        d.registeredAt = block.timestamp;
        d.exists = true;

        devIdOf[account] = devId;
        emit DeveloperRegistered(devId, account, name);
    }

    /// @notice Update your profile (or admin can update any)
    function updateProfile(uint256 devId, string calldata name, string calldata contactURI, string calldata metadataURI)
        external
    {
        Developer storage d = _developers[devId];
        require(d.exists, "Unknown dev");
        require(d.account == msg.sender || _roles[ADMIN][msg.sender], "Not authorized");
        d.name = name;
        d.contactURI = contactURI;
        d.metadataURI = metadataURI;
        emit ProfileUpdated(devId, name, contactURI, metadataURI, msg.sender);
    }

    /// @notice REVIEWER/ADMIN can set verification status
    function setVerified(uint256 devId, bool verified) external {
        require(_roles[REVIEWER][msg.sender] || _roles[ADMIN][msg.sender], "Not reviewer/admin");
        Developer storage d = _developers[devId];
        require(d.exists, "Unknown dev");
        d.verified = verified;
        emit VerificationSet(devId, verified, msg.sender);
    }

    // ---------- Skills ----------
    function addSkill(uint256 devId, bytes32 tag) external {
        Developer storage d = _developers[devId];
        require(d.exists, "Unknown dev");
        require(d.account == msg.sender || _roles[ADMIN][msg.sender], "Not authorized");
        require(tag != bytes32(0), "tag=0");
        if (d.skillIndex[tag] == 0) {
            d.skills.push(tag);
            d.skillIndex[tag] = d.skills.length; // index+1
            emit SkillAdded(devId, tag, msg.sender);
        }
    }

    function removeSkill(uint256 devId, bytes32 tag) external {
        Developer storage d = _developers[devId];
        require(d.exists, "Unknown dev");
        require(d.account == msg.sender || _roles[ADMIN][msg.sender], "Not authorized");
        uint256 idx = d.skillIndex[tag];
        require(idx != 0, "Skill not found");
        uint256 lastIdx = d.skills.length;
        if (idx != lastIdx) {
            bytes32 last = d.skills[lastIdx - 1];
            d.skills[idx - 1] = last;
            d.skillIndex[last] = idx;
        }
        d.skills.pop();
        delete d.skillIndex[tag];
        emit SkillRemoved(devId, tag, msg.sender);
    }

    function skillCount(uint256 devId) external view returns (uint256) {
        return _developers[devId].skills.length;
    }

    function skillAt(uint256 devId, uint256 index) external view returns (bytes32) {
        return _developers[devId].skills[index];
    }

    function listSkills(uint256 devId) external view returns (bytes32[] memory) {
        return _developers[devId].skills;
    }

    // ---------- Projects ----------
    function assignProject(uint256 devId, uint256 projectId) external onlyRole(PROJECT_MANAGER) {
        Developer storage d = _developers[devId];
        require(d.exists, "Unknown dev");
        if (d.projectIndex[projectId] == 0) {
            d.projects.push(projectId);
            d.projectIndex[projectId] = d.projects.length;
            emit ProjectAssigned(devId, projectId, msg.sender);
        }
    }

    function unassignProject(uint256 devId, uint256 projectId) external onlyRole(PROJECT_MANAGER) {
        Developer storage d = _developers[devId];
        require(d.exists, "Unknown dev");
        uint256 idx = d.projectIndex[projectId];
        require(idx != 0, "Not assigned");
        uint256 lastIdx = d.projects.length;
        if (idx != lastIdx) {
            uint256 last = d.projects[lastIdx - 1];
            d.projects[idx - 1] = last;
            d.projectIndex[last] = idx;
        }
        d.projects.pop();
        delete d.projectIndex[projectId];
        emit ProjectUnassigned(devId, projectId, msg.sender);
    }

    function projectCount(uint256 devId) external view returns (uint256) {
        return _developers[devId].projects.length;
    }

    function projectAt(uint256 devId, uint256 index) external view returns (uint256) {
        return _developers[devId].projects[index];
    }

    function listProjects(uint256 devId) external view returns (uint256[] memory) {
        return _developers[devId].projects;
    }

    // ---------- Views ----------
    function getProfile(uint256 devId)
        external
        view
        returns (
            address account,
            string memory name,
            string memory contactURI,
            string memory metadataURI,
            bool verified,
            uint256 registeredAt
        )
    {
        Developer storage d = _developers[devId];
        require(d.exists, "Unknown dev");
        return (d.account, d.name, d.contactURI, d.metadataURI, d.verified, d.registeredAt);
    }

    function developerExists(uint256 devId) external view returns (bool) {
        return _developers[devId].exists;
    }
}
