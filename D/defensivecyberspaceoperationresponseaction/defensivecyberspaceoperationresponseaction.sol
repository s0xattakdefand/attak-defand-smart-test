// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title ExternalDefenseOperations
 * @notice Tracks and manages deliberate, authorized defensive measures taken outside the defended network—
 *         protecting DoD cyberspace capabilities or other designated systems.
 * Sources:
 *   • CNSSI 4009-2015 from DoD JP 3-12
 */
contract ExternalDefenseOperations {
    // Role identifiers
    bytes32 public constant ADMIN_ROLE   = keccak256("ADMIN_ROLE");
    bytes32 public constant PLANNER_ROLE = keccak256("PLANNER_ROLE");
    bytes32 public constant OPERATOR_ROLE= keccak256("OPERATOR_ROLE");
    bytes32 public constant VIEWER_ROLE  = keccak256("VIEWER_ROLE");

    // role => account => granted?
    mapping(bytes32 => mapping(address => bool)) private _roles;

    // Lifecycle status of an operation
    enum Status { Planned, InProgress, Completed, Cancelled }

    // A defensive operation record
    struct Operation {
        uint256    id;
        string     targetNetwork;   // e.g. “Segment-Alpha”, “PartnerNet-3”
        string     description;     // nature of the defensive measure
        address    planner;         // who planned it
        address    operator;        // who’s executing/updating it
        uint256    plannedAt;
        uint256    startedAt;
        uint256    completedAt;
        Status     status;
        bool       exists;
    }

    // Storage of operations by ID
    uint256 public nextOpId;
    mapping(uint256 => Operation) private _operations;

    // Events
    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);

    event OperationPlanned(
        uint256 indexed id,
        string targetNetwork,
        address indexed planner,
        uint256 timestamp
    );
    event OperationStarted(
        uint256 indexed id,
        address indexed operator,
        uint256 timestamp
    );
    event OperationCompleted(
        uint256 indexed id,
        address indexed operator,
        uint256 timestamp
    );
    event OperationCancelled(
        uint256 indexed id,
        address indexed operator,
        uint256 timestamp
    );
    event OperationRead(
        uint256 indexed id,
        address indexed viewer,
        uint256 timestamp
    );

    modifier onlyRole(bytes32 role) {
        require(_roles[role][msg.sender], "EDO: missing role");
        _;
    }

    constructor() {
        // deployer is initial ADMIN, PLANNER, OPERATOR, and VIEWER
        _grantRole(ADMIN_ROLE, msg.sender);
        _grantRole(PLANNER_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(VIEWER_ROLE, msg.sender);
    }

    /// @notice Grant a role to an account (ADMIN only)
    function grantRole(bytes32 role, address account) external onlyRole(ADMIN_ROLE) {
        _grantRole(role, account);
    }

    /// @notice Revoke a role from an account (ADMIN only)
    function revokeRole(bytes32 role, address account) external onlyRole(ADMIN_ROLE) {
        _revokeRole(role, account);
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

    /// @notice Plan a new external defensive operation (PLANNER only)
    function planOperation(string calldata targetNetwork, string calldata description)
        external
        onlyRole(PLANNER_ROLE)
        returns (uint256 opId)
    {
        opId = nextOpId++;
        _operations[opId] = Operation({
            id:            opId,
            targetNetwork: targetNetwork,
            description:   description,
            planner:       msg.sender,
            operator:      address(0),
            plannedAt:     block.timestamp,
            startedAt:     0,
            completedAt:   0,
            status:        Status.Planned,
            exists:        true
        });
        emit OperationPlanned(opId, targetNetwork, msg.sender, block.timestamp);
    }

    /// @notice Start a planned operation (OPERATOR only)
    function startOperation(uint256 opId) external onlyRole(OPERATOR_ROLE) {
        Operation storage op = _operations[opId];
        require(op.exists, "EDO: not found");
        require(op.status == Status.Planned, "EDO: invalid status");
        op.operator   = msg.sender;
        op.startedAt  = block.timestamp;
        op.status     = Status.InProgress;
        emit OperationStarted(opId, msg.sender, block.timestamp);
    }

    /// @notice Complete an in-progress operation (OPERATOR only)
    function completeOperation(uint256 opId) external onlyRole(OPERATOR_ROLE) {
        Operation storage op = _operations[opId];
        require(op.exists, "EDO: not found");
        require(op.status == Status.InProgress, "EDO: invalid status");
        op.completedAt = block.timestamp;
        op.status      = Status.Completed;
        emit OperationCompleted(opId, msg.sender, block.timestamp);
    }

    /// @notice Cancel a planned or in-progress operation (OPERATOR only)
    function cancelOperation(uint256 opId) external onlyRole(OPERATOR_ROLE) {
        Operation storage op = _operations[opId];
        require(op.exists, "EDO: not found");
        require(
            op.status == Status.Planned || op.status == Status.InProgress,
            "EDO: cannot cancel"
        );
        op.status = Status.Cancelled;
        emit OperationCancelled(opId, msg.sender, block.timestamp);
    }

    /// @notice Read details of an operation (VIEWER only)
    function readOperation(uint256 opId)
        external
        onlyRole(VIEWER_ROLE)
        returns (
            string memory targetNetwork,
            string memory description,
            address planner,
            address operator,
            uint256 plannedAt,
            uint256 startedAt,
            uint256 completedAt,
            Status status
        )
    {
        Operation storage op = _operations[opId];
        require(op.exists, "EDO: not found");
        emit OperationRead(opId, msg.sender, block.timestamp);
        return (
            op.targetNetwork,
            op.description,
            op.planner,
            op.operator,
            op.plannedAt,
            op.startedAt,
            op.completedAt,
            op.status
        );
    }

    /// @notice Utility: check role
    function hasRole(bytes32 role, address account) external view returns (bool) {
        return _roles[role][account];
    }
}
