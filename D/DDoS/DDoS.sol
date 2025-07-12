// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * DISTRIBUTED DENIAL OF SERVICE (DDoS) MONITOR
 * NISTIR 7711 — “A denial of service technique that uses numerous hosts to perform the attack.”
 *
 * SECTION 1 — VulnerableDDoSMonitor (⚠️ insecure)
 *   • Anyone can log attacks or mitigation actions.
 *   • No access control or audit of who may record events.
 *
 * SECTION 2 — SecureDDoSMonitor (✅ hardened)
 *   • ADMIN grants MONITOR and MITIGATOR roles.
 *   • MONITORs record attack events (multiple hosts).
 *   • MITIGATORs record mitigation actions against a logged attack.
 *   • Immutable audit trail via events.
 */

/// -------------------------------------------------------------------------
/// SECTION 1 — VulnerableDDoSMonitor
/// -------------------------------------------------------------------------
contract VulnerableDDoSMonitor {
    struct AttackEvent {
        uint256    id;
        address[]  sources;
        string     targetService;
        uint256    timestamp;
        string     mitigation;
    }

    AttackEvent[] public attacks;

    event AttackLogged(uint256 indexed id, address[] sources, string targetService, uint256 timestamp);
    event MitigationLogged(uint256 indexed id, string mitigation, uint256 timestamp);

    /// Anyone can log a DDoS attack
    function logAttack(address[] calldata sources, string calldata targetService) external {
        uint256 id = attacks.length;
        attacks.push(AttackEvent(id, sources, targetService, block.timestamp, ""));
        emit AttackLogged(id, sources, targetService, block.timestamp);
    }

    /// Anyone can log a mitigation action
    function logMitigation(uint256 id, string calldata mitigation) external {
        require(id < attacks.length, "Unknown attack ID");
        attacks[id].mitigation = mitigation;
        emit MitigationLogged(id, mitigation, block.timestamp);
    }
}

/// -------------------------------------------------------------------------
/// SECTION 2 — Helpers: Ownable & RBAC
/// -------------------------------------------------------------------------
abstract contract Ownable {
    address private _owner;
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);
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
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}

abstract contract RBAC is Ownable {
    bytes32 public constant MONITOR_ROLE    = keccak256("MONITOR_ROLE");
    bytes32 public constant MITIGATOR_ROLE  = keccak256("MITIGATOR_ROLE");

    mapping(bytes32 => mapping(address => bool)) private _roles;
    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);

    constructor() {
        // deployer is initial ADMIN, but no MONITOR or MITIGATOR by default
        _grantRole(MONITOR_ROLE, msg.sender);
        _grantRole(MITIGATOR_ROLE, msg.sender);
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
/// SECTION 3 — SecureDDoSMonitor
/// -------------------------------------------------------------------------
contract SecureDDoSMonitor is RBAC {
    struct AttackEvent {
        uint256    id;
        address[]  sources;
        string     targetService;
        uint256    timestamp;
        string     mitigation;
    }

    AttackEvent[] private _attacks;

    event AttackLogged(uint256 indexed id, address[] sources, string targetService, uint256 timestamp);
    event MitigationLogged(uint256 indexed id, string mitigation, uint256 timestamp);

    /// @notice MONITOR logs a DDoS attack event
    function logAttack(address[] calldata sources, string calldata targetService)
        external
        onlyRole(MONITOR_ROLE)
    {
        uint256 id = _attacks.length;
        _attacks.push(AttackEvent(id, sources, targetService, block.timestamp, ""));
        emit AttackLogged(id, sources, targetService, block.timestamp);
    }

    /// @notice MITIGATOR logs a mitigation action against a recorded attack
    function logMitigation(uint256 id, string calldata mitigation)
        external
        onlyRole(MITIGATOR_ROLE)
    {
        require(id < _attacks.length, "Unknown attack ID");
        _attacks[id].mitigation = mitigation;
        emit MitigationLogged(id, mitigation, block.timestamp);
    }

    /// @notice View an attack event’s details
    function getAttack(uint256 id)
        external
        view
        returns (
            address[] memory sources,
            string memory targetService,
            uint256 timestamp,
            string memory mitigation
        )
    {
        AttackEvent storage a = _attacks[id];
        return (a.sources, a.targetService, a.timestamp, a.mitigation);
    }

    /// @notice Total number of logged attacks
    function attackCount() external view returns (uint256) {
        return _attacks.length;
    }
}
