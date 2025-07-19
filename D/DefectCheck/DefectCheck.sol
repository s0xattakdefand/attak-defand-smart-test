// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title DefectCheckSystem
 * @notice Defines defect checks and records their occurrences against assessment objects,
 *         modeling the properties from NISTIR 8011 Vol. 1.
 * @dev Refactored to avoid “stack too deep” by using calldata struct and a storage pointer.
 */
contract DefectCheckSystem {
    // Roles
    bytes32 public constant ADMIN_ROLE     = keccak256("ADMIN_ROLE");
    bytes32 public constant INSPECTOR_ROLE = keccak256("INSPECTOR_ROLE");

    // role → account → granted?
    mapping(bytes32 => mapping(address => bool)) private _roles;

    // Input bundle for defining or updating a check
    struct CheckInput {
        string  testStatement;        // Stated as a test
        bool    automatable;          // Can be automated
        string  desiredState;         // Desired state specification
        string  riskAssessmentInfo;   // Info for control effectiveness/risk
        string  riskResponseOptions;  // Suggested risk responses
        string  subCapability;        // Corresponding sub-capability
    }

    // Stored definition of a defect check
    struct CheckDefinition {
        bool    exists;
        string  testStatement;
        bool    automatable;
        string  desiredState;
        string  riskAssessmentInfo;
        string  riskResponseOptions;
        string  subCapability;
    }
    mapping(bytes32 => CheckDefinition) public definitions;
    bytes32[] public definitionIds;

    // Occurrence of a defect check (pass or fail)
    struct DefectOccurrence {
        bytes32 checkId;
        bytes32 objectId;
        bool    passed;
        string  actualState;
        string  responseChosen;
        address inspector;
        uint256 timestamp;
    }
    mapping(bytes32 => DefectOccurrence[]) private _occurrences;

    // Events
    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);

    event CheckDefined(
        bytes32 indexed checkId,
        string testStatement,
        bool automatable,
        string desiredState,
        string riskAssessmentInfo,
        string riskResponseOptions,
        string subCapability
    );
    event CheckUpdated(
        bytes32 indexed checkId,
        string testStatement,
        bool automatable,
        string desiredState,
        string riskAssessmentInfo,
        string riskResponseOptions,
        string subCapability
    );
    event CheckRemoved(bytes32 indexed checkId);

    event DefectOccurred(
        bytes32 indexed checkId,
        bytes32 indexed objectId,
        bool passed,
        string actualState,
        string responseChosen,
        address indexed inspector,
        uint256 timestamp
    );

    modifier onlyRole(bytes32 role) {
        require(_roles[role][msg.sender], "DefectCheckSystem: missing role");
        _;
    }

    constructor() {
        _grantRole(ADMIN_ROLE, msg.sender);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Role management
    // ─────────────────────────────────────────────────────────────────────────
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

    // ─────────────────────────────────────────────────────────────────────────
    // Define a new defect check
    // ─────────────────────────────────────────────────────────────────────────
    function defineCheck(bytes32 checkId, CheckInput calldata input)
        external
        onlyRole(ADMIN_ROLE)
    {
        CheckDefinition storage def = definitions[checkId];
        require(!def.exists, "DefectCheckSystem: already defined");

        def.exists            = true;
        def.testStatement     = input.testStatement;
        def.automatable       = input.automatable;
        def.desiredState      = input.desiredState;
        def.riskAssessmentInfo= input.riskAssessmentInfo;
        def.riskResponseOptions= input.riskResponseOptions;
        def.subCapability     = input.subCapability;

        definitionIds.push(checkId);

        emit CheckDefined(
            checkId,
            input.testStatement,
            input.automatable,
            input.desiredState,
            input.riskAssessmentInfo,
            input.riskResponseOptions,
            input.subCapability
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Update an existing defect check
    // ─────────────────────────────────────────────────────────────────────────
    function updateCheck(bytes32 checkId, CheckInput calldata input)
        external
        onlyRole(ADMIN_ROLE)
    {
        CheckDefinition storage def = definitions[checkId];
        require(def.exists, "DefectCheckSystem: unknown check");

        def.testStatement      = input.testStatement;
        def.automatable        = input.automatable;
        def.desiredState       = input.desiredState;
        def.riskAssessmentInfo = input.riskAssessmentInfo;
        def.riskResponseOptions= input.riskResponseOptions;
        def.subCapability      = input.subCapability;

        emit CheckUpdated(
            checkId,
            input.testStatement,
            input.automatable,
            input.desiredState,
            input.riskAssessmentInfo,
            input.riskResponseOptions,
            input.subCapability
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Remove a defect check definition
    // ─────────────────────────────────────────────────────────────────────────
    function removeCheck(bytes32 checkId) external onlyRole(ADMIN_ROLE) {
        CheckDefinition storage def = definitions[checkId];
        require(def.exists, "DefectCheckSystem: unknown check");
        delete definitions[checkId];

        // remove from definitionIds array
        uint256 len = definitionIds.length;
        for (uint256 i = 0; i < len; i++) {
            if (definitionIds[i] == checkId) {
                definitionIds[i] = definitionIds[len - 1];
                definitionIds.pop();
                break;
            }
        }

        emit CheckRemoved(checkId);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Record an occurrence of a defect check
    // ─────────────────────────────────────────────────────────────────────────
    function recordOccurrence(
        bytes32 checkId,
        bytes32 objectId,
        bool passed,
        string calldata actualState,
        string calldata responseChosen
    )
        external
        onlyRole(INSPECTOR_ROLE)
    {
        require(definitions[checkId].exists, "DefectCheckSystem: unknown check");

        _occurrences[objectId].push(DefectOccurrence({
            checkId:       checkId,
            objectId:      objectId,
            passed:        passed,
            actualState:   actualState,
            responseChosen:responseChosen,
            inspector:     msg.sender,
            timestamp:     block.timestamp
        }));

        emit DefectOccurred(
            checkId,
            objectId,
            passed,
            actualState,
            responseChosen,
            msg.sender,
            block.timestamp
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Query helpers
    // ─────────────────────────────────────────────────────────────────────────
    function getDefinitionIds() external view returns (bytes32[] memory) {
        return definitionIds;
    }
    function getOccurrenceCount(bytes32 objectId) external view returns (uint256) {
        return _occurrences[objectId].length;
    }
    function getOccurrence(bytes32 objectId, uint256 index)
        external
        view
        returns (
            bytes32 checkId,
            bool    passed,
            string memory actualState,
            string memory responseChosen,
            address inspector,
            uint256 timestamp
        )
    {
        DefectOccurrence storage occ = _occurrences[objectId][index];
        return (
            occ.checkId,
            occ.passed,
            occ.actualState,
            occ.responseChosen,
            occ.inspector,
            occ.timestamp
        );
    }
}
