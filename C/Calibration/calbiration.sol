// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title CalibrationSuite.sol
/// @notice On‐chain analogues of “Calibration” patterns:
///   Types: Manual, Automatic, SelfTest, ExternalStandard  
///   AttackTypes: SensorDrift, DataTampering, ReplayAttack, SignalJamming  
///   DefenseTypes: AccessControl, RangeCheck, TimestampValidation, SignatureValidation, RateLimit

enum CalibrationType          { Manual, Automatic, SelfTest, ExternalStandard }
enum CalibrationAttackType    { SensorDrift, DataTampering, ReplayAttack, SignalJamming }
enum CalibrationDefenseType   { AccessControl, RangeCheck, TimestampValidation, SignatureValidation, RateLimit }

error CAL__NotAuthorized();
error CAL__InvalidValue();
error CAL__TooManyRequests();
error CAL__InvalidSignature();
error CAL__InvalidTimestamp();
error CAL__ReplayDetected();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE CALIBRATION MANAGER
//    • ❌ no checks: any value accepted → SensorDrift / DataTampering
////////////////////////////////////////////////////////////////////////////////
contract CalibrationVuln {
    mapping(uint256 => int256) public readings;

    event CalibrationPerformed(
        address indexed who,
        uint256         sensorId,
        int256          value,
        CalibrationType ctype,
        CalibrationAttackType attack
    );

    function calibrate(
        uint256 sensorId,
        int256  value,
        CalibrationType ctype
    ) external {
        readings[sensorId] = value;
        emit CalibrationPerformed(
            msg.sender,
            sensorId,
            value,
            ctype,
            CalibrationAttackType.SensorDrift
        );
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates drift, tampering, replay, jamming
////////////////////////////////////////////////////////////////////////////////
contract Attack_Calibration {
    CalibrationVuln public target;
    uint256 public lastSensor;
    int256  public lastValue;

    constructor(CalibrationVuln _t) {
        target = _t;
    }

    function drift(uint256 sensorId, int256 offset) external {
        int256 current = target.readings(sensorId);
        int256 bumped = current + offset;
        target.calibrate(sensorId, bumped, CalibrationType.Manual);
        lastSensor = sensorId;
        lastValue  = bumped;
    }

    function tamper(uint256 sensorId, int256 fakeValue) external {
        target.calibrate(sensorId, fakeValue, CalibrationType.Automatic);
    }

    function replay() external {
        // reuse last parameters
        target.calibrate(lastSensor, lastValue, CalibrationType.Manual);
    }

    function jam(uint256 sensorId) external {
        // simulate jamming by zeroing out
        target.calibrate(sensorId, 0, CalibrationType.ExternalStandard);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may calibrate
////////////////////////////////////////////////////////////////////////////////
contract CalibrationSafeAccess {
    mapping(uint256 => int256) public readings;
    address public owner;

    event CalibrationPerformed(
        address indexed who,
        uint256         sensorId,
        int256          value,
        CalibrationType ctype,
        CalibrationDefenseType defense
    );

    constructor() {
        owner = msg.sender;
    }

    function calibrate(
        uint256 sensorId,
        int256  value,
        CalibrationType ctype
    ) external {
        if (msg.sender != owner) revert CAL__NotAuthorized();
        readings[sensorId] = value;
        emit CalibrationPerformed(
            msg.sender,
            sensorId,
            value,
            ctype,
            CalibrationDefenseType.AccessControl
        );
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH RANGE CHECK & RATE LIMIT
//    • ✅ Defense: RangeCheck – enforce MIN/MAX  
//               RateLimit – cap calls per block
////////////////////////////////////////////////////////////////////////////////
contract CalibrationSafeValidate {
    mapping(uint256 => int256) public readings;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;

    int256  public constant MIN_VALUE = -1000;
    int256  public constant MAX_VALUE =  1000;
    uint256 public constant MAX_CALLS =  5;

    event CalibrationPerformed(
        address indexed who,
        uint256         sensorId,
        int256          value,
        CalibrationType ctype,
        CalibrationDefenseType defense
    );

    function calibrate(
        uint256 sensorId,
        int256  value,
        CalibrationType ctype
    ) external {
        if (value < MIN_VALUE || value > MAX_VALUE) revert CAL__InvalidValue();

        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert CAL__TooManyRequests();

        readings[sensorId] = value;
        emit CalibrationPerformed(
            msg.sender,
            sensorId,
            value,
            ctype,
            CalibrationDefenseType.RangeCheck
        );
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE & TIMESTAMP VALIDATION
//    • ✅ Defense: SignatureValidation – require signer’s signature  
//               TimestampValidation – require recent signed timestamp  
//               RateLimit           – cap calls per block
////////////////////////////////////////////////////////////////////////////////
contract CalibrationSafeAdvanced {
    mapping(uint256 => int256) public readings;
    mapping(bytes32  => bool) public seen;
    mapping(address  => uint256) public lastBlock;
    mapping(address  => uint256) public callsInBlock;

    address public signer;
    uint256 public constant MAX_AGE    = 5 minutes;
    uint256 public constant MAX_CALLS  = 5;

    event CalibrationPerformed(
        address indexed who,
        uint256         sensorId,
        int256          value,
        CalibrationType ctype,
        CalibrationDefenseType defense
    );

    constructor(address _signer) {
        signer = _signer;
    }

    function calibrate(
        uint256  sensorId,
        int256   value,
        CalibrationType ctype,
        uint256  timestamp,
        bytes32  nonce,
        bytes    calldata sig
    ) external {
        // timestamp freshness
        if (block.timestamp < timestamp || block.timestamp > timestamp + MAX_AGE)
            revert CAL__InvalidTimestamp();

        // replay guard
        bytes32 key = keccak256(abi.encodePacked(sensorId, value, ctype, timestamp, nonce));
        if (seen[key]) revert CAL__ReplayDetected();
        seen[key] = true;

        // rate-limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert CAL__TooManyRequests();

        // signature verification
        bytes32 h      = keccak256(abi.encodePacked(sensorId, value, ctype, timestamp, nonce));
        bytes32 ethMsg = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8,bytes32,bytes32));
        if (ecrecover(ethMsg, v, r, s) != signer) revert CAL__InvalidSignature();

        readings[sensorId] = value;
        emit CalibrationPerformed(
            msg.sender,
            sensorId,
            value,
            ctype,
            CalibrationDefenseType.SignatureValidation
        );
    }
}
