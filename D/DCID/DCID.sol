// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * DIRECTOR CENTRAL INTELLIGENCE DIRECTIVE (DCID) REGISTRY
 * — Manages directives issued by the DCI, with role‐based controls for issuing and revoking.
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
    bytes32 public constant DCI_ROLE     = keccak256("DCI_ROLE");
    bytes32 public constant AGENCY_ROLE  = keccak256("AGENCY_ROLE");

    mapping(bytes32 => mapping(address => bool)) private _roles;
    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);

    constructor() {
        _grantRole(DCI_ROLE, msg.sender);
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
/// SECTION 2 — DCID Registry
/// -------------------------------------------------------------------------
contract DCIDRegistry is RBAC {
    enum Status { ACTIVE, REVOKED }

    struct Directive {
        uint256    id;
        string     title;
        string     content;
        address    issuer;      // must have DCI_ROLE
        uint256    timestamp;
        Status     status;
    }

    uint256 public nextId;
    mapping(uint256 => Directive) private _directives;

    // Agency registration
    event AgencyRegistered(address indexed agency);
    event AgencyRevoked(address indexed agency);

    // Directive lifecycle
    event DirectiveIssued(
        uint256 indexed id,
        string title,
        address indexed issuer,
        uint256 timestamp
    );
    event DirectiveRevoked(
        uint256 indexed id,
        address indexed revoker,
        uint256 timestamp
    );

    /// @notice DCI registers an agency
    function registerAgency(address agency) external onlyRole(DCI_ROLE) {
        _grantRole(AGENCY_ROLE, agency);
        emit AgencyRegistered(agency);
    }

    /// @notice DCI revokes agency status
    function revokeAgency(address agency) external onlyRole(DCI_ROLE) {
        _revokeRole(AGENCY_ROLE, agency);
        emit AgencyRevoked(agency);
    }

    /// @notice Issue a new directive (only DCI_ROLE)
    function issueDirective(string calldata title, string calldata content)
        external
        onlyRole(DCI_ROLE)
        returns (uint256 id)
    {
        id = nextId++;
        _directives[id] = Directive({
            id:        id,
            title:     title,
            content:   content,
            issuer:    msg.sender,
            timestamp: block.timestamp,
            status:    Status.ACTIVE
        });
        emit DirectiveIssued(id, title, msg.sender, block.timestamp);
    }

    /// @notice Revoke an existing directive (only DCI_ROLE)
    function revokeDirective(uint256 id) external onlyRole(DCI_ROLE) {
        Directive storage d = _directives[id];
        require(d.issuer != address(0), "Unknown directive");
        require(d.status == Status.ACTIVE, "Already revoked");
        d.status = Status.REVOKED;
        emit DirectiveRevoked(id, msg.sender, block.timestamp);
    }

    /// @notice View directive details
    function getDirective(uint256 id)
        external
        view
        returns (
            string memory title,
            string memory content,
            address issuer,
            uint256 timestamp,
            Status status
        )
    {
        Directive storage d = _directives[id];
        require(d.issuer != address(0), "Unknown directive");
        return (d.title, d.content, d.issuer, d.timestamp, d.status);
    }

    /// @notice List all directive IDs (for off-chain indexing)
    function totalDirectives() external view returns (uint256) {
        return nextId;
    }
}
