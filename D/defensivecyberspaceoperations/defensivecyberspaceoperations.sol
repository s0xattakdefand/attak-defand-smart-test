// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title DefensiveCyberspaceOperations
 * @notice Tracks passive and active cyberspace operations intended to preserve friendly cyberspace capabilities
 *         and protect data, networks, and other designated systems.
 * Sources:
 *   • CNSSI 4009-2015 from DoD JP 3-12
 */
contract DefensiveCyberspaceOperations {
    // Roles
    bytes32 public constant ADMIN_ROLE     = keccak256("ADMIN_ROLE");
    bytes32 public constant PLANNER_ROLE   = keccak256("PLANNER_ROLE");
    bytes32 public constant OPERATOR_ROLE  = keccak256("OPERATOR_ROLE");
    bytes32 public constant VIEWER_ROLE    = keccak256("VIEWER_ROLE");

    // Operation types
    enum OperationType { Passive, Active }
    // Lifecycle status
    enum Status { Planned, Executing, Completed, Cancelled }

    struct Operation {
        uint256       id;
        OperationType opType;
        string        target;       // e.g. network segment or system identifier
        string        description;
        address       planner;
        address       operator;
        uint256       plannedAt;
        uint256       executedAt;
        uint256       completedAt;
        Status        status;
        bool          exists;
    }

    uint256 public nextOpId;
    mapping(uint256 => Operation) private _operations;
    mapping(bytes32 => mapping(address => bool)) private _roles;

    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);

    event OperationPlanned(
        uint256 indexed id,
        OperationType opType,
        string target,
        address indexed planner,
        uint256 timestamp
    );
    event OperationExecuted(
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
        require(_roles[role][msg.sender], "DCO: missing role");
        _;
    }

    constructor() {
        _grantRole(ADMIN_ROLE, msg.sender);
        _grantRole(PLANNER_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(VIEWER_ROLE, msg.sender);
    }

    // Role management
    function grantRole(bytes32 role, address account) external onlyRole(ADMIN_ROLE) {
        _grantRole(role, account);
    }
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

    /// @notice Plan a new cyberspace operation
    function planOperation(
        OperationType opType,
        string calldata target,
        string calldata description
    )
        external
        onlyRole(PLANNER_ROLE)
        returns (uint256 opId)
    {
        opId = nextOpId++;
        _operations[opId] = Operation({
            id:          opId,
            opType:      opType,
            target:      target,
            description: description,
            planner:     msg.sender,
            operator:    address(0),
            plannedAt:   block.timestamp,
            executedAt:  0,
            completedAt: 0,
            status:      Status.Planned,
            exists:      true
        });
        emit OperationPlanned(opId, opType, target, msg.sender, block.timestamp);
    }

    /// @notice Execute a planned operation
    function executeOperation(uint256 opId) external onlyRole(OPERATOR_ROLE) {
        Operation storage op = _operations[opId];
        require(op.exists,      "DCO: not found");
        require(op.status == Status.Planned, "DCO: invalid status");
        op.operator   = msg.sender;
        op.executedAt = block.timestamp;
        op.status     = Status.Executing;
        emit OperationExecuted(opId, msg.sender, block.timestamp);
    }

    /// @notice Complete an executing operation
    function completeOperation(uint256 opId) external onlyRole(OPERATOR_ROLE) {
        Operation storage op = _operations[opId];
        require(op.exists,         "DCO: not found");
        require(op.status == Status.Executing, "DCO: invalid status");
        op.completedAt = block.timestamp;
        op.status      = Status.Completed;
        emit OperationCompleted(opId, msg.sender, block.timestamp);
    }

    /// @notice Cancel a planned or executing operation
    function cancelOperation(uint256 opId) external onlyRole(OPERATOR_ROLE) {
        Operation storage op = _operations[opId];
        require(op.exists,  "DCO: not found");
        require(
            op.status == Status.Planned || op.status == Status.Executing,
            "DCO: cannot cancel"
        );
        op.status = Status.Cancelled;
        emit OperationCancelled(opId, msg.sender, block.timestamp);
    }

    /// @notice Read operation details (emits audit)
    function readOperation(uint256 opId)
        external
        onlyRole(VIEWER_ROLE)
        returns (
            OperationType opType,
            string memory target,
            string memory description,
            address planner,
            address operator,
            uint256 plannedAt,
            uint256 executedAt,
            uint256 completedAt,
            Status status
        )
    {
        Operation storage op = _operations[opId];
        require(op.exists, "DCO: not found");
        emit OperationRead(opId, msg.sender, block.timestamp);
        return (
            op.opType,
            op.target,
            op.description,
            op.planner,
            op.operator,
            op.plannedAt,
            op.executedAt,
            op.completedAt,
            op.status
        );
    }
}
