// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * DEFENSIVE CYBERSPACE OPERATION RESPONSE ACTIONS
 * — Manages response actions tied to detected cyberspace incidents,
 *   with role‐based controls and full audit logging.
 */

/// -------------------------------------------------------------------------
/// SECTION 1 — Ownable & RBAC Helpers
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
    bytes32 public constant DEFENDER_ROLE = keccak256("DEFENDER_ROLE");
    bytes32 public constant RESPONDER_ROLE = keccak256("RESPONDER_ROLE");

    mapping(bytes32 => mapping(address => bool)) private _roles;
    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);

    constructor() {
        _grantRole(DEFENDER_ROLE, msg.sender);
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
/// SECTION 2 — Response Action Manager
/// -------------------------------------------------------------------------
contract ResponseActionManager is RBAC {
    enum ActionStatus { PENDING, ASSIGNED, EXECUTED, ABORTED }

    struct Action {
        uint256    id;
        uint256    incidentId;
        string     description;
        ActionStatus status;
        address    createdBy;
        address    assignedTo;
        uint256    createdAt;
        uint256    executedAt;
    }

    uint256 public nextActionId;
    mapping(uint256 => Action) private _actions;

    event ActionCreated(
        uint256 indexed id,
        uint256 indexed incidentId,
        string description,
        address indexed createdBy,
        uint256 timestamp
    );
    event ActionAssigned(
        uint256 indexed id,
        address indexed assignedTo,
        address indexed assignedBy,
        uint256 timestamp
    );
    event ActionExecuted(
        uint256 indexed id,
        address indexed executedBy,
        uint256 timestamp
    );
    event ActionAborted(
        uint256 indexed id,
        address indexed abortedBy,
        uint256 timestamp
    );

    /// @notice DEFENDER logs a new response action for an incident
    function createAction(uint256 incidentId, string calldata description)
        external
        onlyRole(DEFENDER_ROLE)
        returns (uint256 id)
    {
        id = nextActionId++;
        _actions[id] = Action({
            id:           id,
            incidentId:   incidentId,
            description:  description,
            status:       ActionStatus.PENDING,
            createdBy:    msg.sender,
            assignedTo:   address(0),
            createdAt:    block.timestamp,
            executedAt:   0
        });
        emit ActionCreated(id, incidentId, description, msg.sender, block.timestamp);
    }

    /// @notice DEFENDER assigns a PENDING action to a RESPONDER
    function assignAction(uint256 id, address responder)
        external
        onlyRole(DEFENDER_ROLE)
    {
        Action storage act = _actions[id];
        require(act.status == ActionStatus.PENDING, "Action not pending");
        require(hasRole(RESPONDER_ROLE, responder), "Assignee not responder");
        act.assignedTo = responder;
        act.status = ActionStatus.ASSIGNED;
        emit ActionAssigned(id, responder, msg.sender, block.timestamp);
    }

    /// @notice RESPONDER executes an ASSIGNED action
    function executeAction(uint256 id)
        external
        onlyRole(RESPONDER_ROLE)
    {
        Action storage act = _actions[id];
        require(act.status == ActionStatus.ASSIGNED, "Action not assigned");
        require(act.assignedTo == msg.sender, "Not assigned to you");
        act.status = ActionStatus.EXECUTED;
        act.executedAt = block.timestamp;
        emit ActionExecuted(id, msg.sender, block.timestamp);
    }

    /// @notice DEFENDER may abort a PENDING or ASSIGNED action
    function abortAction(uint256 id)
        external
        onlyRole(DEFENDER_ROLE)
    {
        Action storage act = _actions[id];
        require(
            act.status == ActionStatus.PENDING || act.status == ActionStatus.ASSIGNED,
            "Cannot abort"
        );
        act.status = ActionStatus.ABORTED;
        emit ActionAborted(id, msg.sender, block.timestamp);
    }

    /// @notice View details of a response action
    function getAction(uint256 id)
        external
        view
        returns (
            uint256    actionId,
            uint256    incidentId,
            string memory description,
            ActionStatus status,
            address    createdBy,
            address    assignedTo,
            uint256    createdAt,
            uint256    executedAt
        )
    {
        Action storage act = _actions[id];
        return (
            act.id,
            act.incidentId,
            act.description,
            act.status,
            act.createdBy,
            act.assignedTo,
            act.createdAt,
            act.executedAt
        );
    }
}
