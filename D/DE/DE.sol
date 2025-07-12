// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * CYBERSECURITY EVENT DETECTION CONTRACT
 * Implements the “Detect” function from NIST CSF v1.1 (NIST SP 800-37 Rev.2)
 * by allowing definition of detection rules and logging of events that
 * trigger alerts when matching rules are met.
 *
 * Roles:
 *  • DETECT_ADMIN – can add/remove detection rules and manage MONITORs.
 *  • MONITOR      – can report suspected cybersecurity events.
 *
 * Workflow:
 *  1) DETECT_ADMIN calls addRule(eventType) to enable detection of that type.
 *  2) DETECT_ADMIN grants MONITOR role to monitoring agents.
 *  3) MONITOR calls reportEvent(eventType, metadataPtr):
 *       • always logs the event
 *       • if a rule exists for eventType, emits a DetectionAlert
 *  4) Off-chain systems subscribe to DetectionAlert for real-time response.
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
    bytes32 public constant DETECT_ADMIN = keccak256("DETECT_ADMIN");
    bytes32 public constant MONITOR      = keccak256("MONITOR");

    mapping(bytes32 => mapping(address => bool)) private _roles;
    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);

    constructor() {
        // deployer is initial DETECT_ADMIN
        _grantRole(DETECT_ADMIN, msg.sender);
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
/// SECTION 2 — CyberDetect contract
/// -------------------------------------------------------------------------
contract CyberDetect is RBAC {
    // Detection rules: eventType → enabled?
    mapping(bytes32 => bool) public ruleEnabled;

    // Log of reported events
    struct EventLog {
        uint256    id;
        bytes32    eventType;
        string     metadataPtr;  // e.g., IPFS CID, external log reference
        address    reporter;
        uint256    timestamp;
        bool       triggered;    // whether detection rule matched
    }

    EventLog[] public logs;

    // Events for off-chain subscribers
    event RuleAdded(bytes32 indexed eventType);
    event RuleRemoved(bytes32 indexed eventType);
    event EventReported(
        uint256 indexed id,
        bytes32 indexed eventType,
        address indexed reporter,
        bool triggered,
        uint256 timestamp
    );
    event DetectionAlert(uint256 indexed id, bytes32 indexed eventType, address indexed reporter);

    /// @notice DETECT_ADMIN adds a new detection rule
    function addRule(bytes32 eventType) external onlyRole(DETECT_ADMIN) {
        require(!ruleEnabled[eventType], "Rule already enabled");
        ruleEnabled[eventType] = true;
        emit RuleAdded(eventType);
    }

    /// @notice DETECT_ADMIN removes an existing detection rule
    function removeRule(bytes32 eventType) external onlyRole(DETECT_ADMIN) {
        require(ruleEnabled[eventType], "Rule not enabled");
        ruleEnabled[eventType] = false;
        emit RuleRemoved(eventType);
    }

    /// @notice MONITOR reports a cybersecurity event instance
    /// @param eventType   Identifier for the type of event (e.g. "UNAUTHORIZED_ACCESS")
    /// @param metadataPtr Off-chain reference to detailed logs or telemetry
    function reportEvent(bytes32 eventType, string calldata metadataPtr)
        external
        onlyRole(MONITOR)
    {
        bool triggered = ruleEnabled[eventType];
        uint256 id = logs.length;
        logs.push(EventLog({
            id:          id,
            eventType:   eventType,
            metadataPtr: metadataPtr,
            reporter:    msg.sender,
            timestamp:   block.timestamp,
            triggered:   triggered
        }));

        emit EventReported(id, eventType, msg.sender, triggered, block.timestamp);
        if (triggered) {
            emit DetectionAlert(id, eventType, msg.sender);
        }
    }

    /// @notice Total number of logged events
    function logCount() external view returns (uint256) {
        return logs.length;
    }

    /// @notice Retrieve a logged event by ID
    function getLog(uint256 id)
        external
        view
        returns (
            bytes32 eventType,
            string memory metadataPtr,
            address reporter,
            uint256 timestamp,
            bool triggered
        )
    {
        EventLog storage e = logs[id];
        return (e.eventType, e.metadataPtr, e.reporter, e.timestamp, e.triggered);
    }
}
