// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * DETECT: ANOMALIES AND EVENTS DEMO
 * Implements the “Detect” function of NIST CSF v1.1 – “Anomalies and Events”
 *
 * Roles:
 *  • ADMIN     – grants/revokes DETECTORs and manages anomaly definitions
 *  • DETECTOR  – logs normal events and reports anomalies
 *
 * Features:
 *  1) ADMIN can add/remove anomaly types (bytes32 identifiers)
 *  2) ADMIN can grant/revoke DETECTOR role to accounts
 *  3) DETECTOR calls reportEvent(...) to log any event
 *  4) DETECTOR calls reportAnomaly(...) only for defined anomaly types, triggering an alert
 *  5) All reports are immutably logged in arrays and via events
 */

/// -------------------------------------------------------------------------
/// SECTION 1 — Ownable & RBAC Helpers
/// -------------------------------------------------------------------------
abstract contract Ownable {
    address private _owner;
    event OwnershipTransferred(address indexed previous, address indexed next);

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
        require(newOwner != address(0), "Ownable: zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}

abstract contract RBAC is Ownable {
    bytes32 public constant DETECTOR_ROLE = keccak256("DETECTOR_ROLE");

    mapping(bytes32 => mapping(address => bool)) private _roles;
    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);

    constructor() {
        // deployer is implicitly ADMIN but must grant themselves DETECTOR if desired
    }

    modifier onlyRole(bytes32 role) {
        require(_roles[role][msg.sender], "RBAC: access denied");
        _;
    }

    function grantRole(bytes32 role, address account) external onlyOwner {
        require(!_roles[role][account], "RBAC: already granted");
        _roles[role][account] = true;
        emit RoleGranted(role, account);
    }

    function revokeRole(bytes32 role, address account) external onlyOwner {
        require(_roles[role][account], "RBAC: not granted");
        _roles[role][account] = false;
        emit RoleRevoked(role, account);
    }

    function hasRole(bytes32 role, address account) public view returns (bool) {
        return _roles[role][account];
    }
}

/// -------------------------------------------------------------------------
/// SECTION 2 — DetectAnomaliesAndEvents Contract
/// -------------------------------------------------------------------------
contract DetectAnomaliesAndEvents is RBAC {
    // anomalyType => defined?
    mapping(bytes32 => bool) public anomalyTypes;

    struct LogEntry {
        uint256 id;
        bytes32 typ;        // eventType or anomalyType
        string  metadata;   // off-chain pointer/description
        address reporter;
        uint256 timestamp;
        bool    isAnomaly;
    }

    LogEntry[] public logs;

    event AnomalyTypeAdded(bytes32 indexed anomalyType);
    event AnomalyTypeRemoved(bytes32 indexed anomalyType);
    event EventReported(
        uint256 indexed id,
        bytes32 indexed eventType,
        address indexed reporter,
        uint256 timestamp
    );
    event AnomalyReported(
        uint256 indexed id,
        bytes32 indexed anomalyType,
        address indexed reporter,
        uint256 timestamp
    );

    /// @notice ADMIN defines a new anomaly type
    function addAnomalyType(bytes32 anomalyType) external onlyOwner {
        require(!anomalyTypes[anomalyType], "Already defined");
        anomalyTypes[anomalyType] = true;
        emit AnomalyTypeAdded(anomalyType);
    }

    /// @notice ADMIN removes a defined anomaly type
    function removeAnomalyType(bytes32 anomalyType) external onlyOwner {
        require(anomalyTypes[anomalyType], "Not defined");
        anomalyTypes[anomalyType] = false;
        emit AnomalyTypeRemoved(anomalyType);
    }

    /// @notice DETECTOR logs a normal event
    function reportEvent(bytes32 eventType, string calldata metadata)
        external
        onlyRole(DETECTOR_ROLE)
    {
        uint256 id = logs.length;
        logs.push(LogEntry({
            id:         id,
            typ:        eventType,
            metadata:   metadata,
            reporter:   msg.sender,
            timestamp:  block.timestamp,
            isAnomaly:  false
        }));
        emit EventReported(id, eventType, msg.sender, block.timestamp);
    }

    /// @notice DETECTOR reports an anomaly of a defined type
    function reportAnomaly(bytes32 anomalyType, string calldata metadata)
        external
        onlyRole(DETECTOR_ROLE)
    {
        require(anomalyTypes[anomalyType], "Unknown anomaly type");
        uint256 id = logs.length;
        logs.push(LogEntry({
            id:         id,
            typ:        anomalyType,
            metadata:   metadata,
            reporter:   msg.sender,
            timestamp:  block.timestamp,
            isAnomaly:  true
        }));
        emit AnomalyReported(id, anomalyType, msg.sender, block.timestamp);
    }

    /// @notice Retrieve total number of logged entries
    function logCount() external view returns (uint256) {
        return logs.length;
    }

    /// @notice Fetch a specific log entry
    function getLog(uint256 id)
        external
        view
        returns (
            bytes32 typ,
            string memory metadata,
            address reporter,
            uint256 timestamp,
            bool isAnomaly
        )
    {
        LogEntry storage e = logs[id];
        return (e.typ, e.metadata, e.reporter, e.timestamp, e.isAnomaly);
    }
}
