// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * DEFENSE CYBER CRIME CENTER (DC3) DEMO
 * — Illustrates a registry of cyber-crime incidents maintained by the
 *   Defense Cyber Crime Center, with granular roles for Admins,
 *   Investigators, and Analysts, and full event‐driven audit logging.
 */

/// -------------------------------------------------------------------------
/// SECTION 1 — Ownable & RBAC helpers
/// -------------------------------------------------------------------------
abstract contract Ownable {
    address private _owner;
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor() {
        _owner = msg.sender;
        emit OwnershipTransferred(address(0), _owner);
    }

    modifier onlyOwner() {
        require(msg.sender == _owner, "Ownable: caller is not owner");
        _;
    }

    function owner() public view returns (address) {
        return _owner;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}

abstract contract RBAC is Ownable {
    bytes32 public constant ADMIN_ROLE         = keccak256("ADMIN");
    bytes32 public constant INVESTIGATOR_ROLE  = keccak256("INVESTIGATOR");
    bytes32 public constant ANALYST_ROLE       = keccak256("ANALYST");

    mapping(bytes32 => mapping(address => bool)) private _roles;

    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);

    constructor() {
        _grantRole(ADMIN_ROLE, msg.sender);
    }

    modifier onlyRole(bytes32 role) {
        require(_roles[role][msg.sender], "RBAC: access denied");
        _;
    }

    function grantRole(bytes32 role, address account) external onlyOwner {
        _grantRole(role, account);
    }

    function revokeRole(bytes32 role, address account) external onlyOwner {
        _revokeRole(role, account);
    }

    function hasRole(bytes32 role, address account) public view returns (bool) {
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
}

/// -------------------------------------------------------------------------
/// SECTION 2 — DC3 Incident Registry
/// -------------------------------------------------------------------------
contract DefenseCyberCrimeCenter is RBAC {
    enum Status { REPORTED, INVESTIGATING, RESOLVED }

    struct Incident {
        uint256      id;
        string       description;
        address      reporter;
        uint256      reportedAt;
        Status       status;
        address      investigator;
        uint256      updatedAt;
    }

    uint256 public nextIncidentId;
    mapping(uint256 => Incident) private _incidents;

    /// Audit events
    event IncidentReported(
        uint256 indexed id,
        address indexed reporter,
        string description,
        uint256 timestamp
    );
    event StatusUpdated(
        uint256 indexed id,
        Status indexed status,
        address indexed by,
        uint256 timestamp
    );
    event InvestigatorAssigned(
        uint256 indexed id,
        address indexed investigator,
        address indexed assignedBy,
        uint256 timestamp
    );

    /// Report a new incident (INVESTIGATOR only)
    function reportIncident(string calldata description) external onlyRole(INVESTIGATOR_ROLE) {
        uint256 id = nextIncidentId++;
        _incidents[id] = Incident({
            id:            id,
            description:   description,
            reporter:      msg.sender,
            reportedAt:    block.timestamp,
            status:        Status.REPORTED,
            investigator:  address(0),
            updatedAt:     block.timestamp
        });
        emit IncidentReported(id, msg.sender, description, block.timestamp);
    }

    /// Assign an investigator to an incident (ADMIN only)
    function assignInvestigator(uint256 id, address investigator) external onlyRole(ADMIN_ROLE) {
        require(hasRole(INVESTIGATOR_ROLE, investigator), "Not an investigator");
        Incident storage inc = _incidents[id];
        inc.investigator = investigator;
        inc.updatedAt = block.timestamp;
        emit InvestigatorAssigned(id, investigator, msg.sender, block.timestamp);
    }

    /// Update status of an incident (assigned investigator or ADMIN)
    function updateStatus(uint256 id, Status status) external {
        Incident storage inc = _incidents[id];
        require(
            msg.sender == inc.investigator || hasRole(ADMIN_ROLE, msg.sender),
            "Not authorized to update"
        );
        inc.status = status;
        inc.updatedAt = block.timestamp;
        emit StatusUpdated(id, status, msg.sender, block.timestamp);
    }

    /// View incident details (INVESTIGATOR, ANALYST, or ADMIN)
    function viewIncident(uint256 id)
        external
        view
        onlyRole(ANALYST_ROLE)
        returns (
            uint256      incidentId,
            string memory description,
            address      reporter,
            uint256      reportedAt,
            Status       status,
            address      investigator,
            uint256      updatedAt
        )
    {
        Incident storage inc = _incidents[id];
        return (
            inc.id,
            inc.description,
            inc.reporter,
            inc.reportedAt,
            inc.status,
            inc.investigator,
            inc.updatedAt
        );
    }
}
