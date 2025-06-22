// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title WorldGeodeticSystemSuite.sol
/// @notice On-chain analogues of “World Geodetic System” coordinate reporting patterns:
///   Types: WGS84, WGS72, WGS67, CustomDatum  
///   AttackTypes: Spoofing, Jamming, Replay, DataManipulation  
///   DefenseTypes: SignatureValidation, MultiSource, TimestampValidation, RateLimit

enum WGSSystemType           { WGS84, WGS72, WGS67, CustomDatum }
enum WGSSAttackType          { Spoofing, Jamming, Replay, DataManipulation }
enum WGSDefenseType          { SignatureValidation, MultiSource, TimestampValidation, RateLimit }

error WGS__InvalidSignature();
error WGS__TooManyRequests();
error WGS__InvalidTimestamp();
error WGS__AlreadyReported();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE REPORTER
//    • ❌ no checks: any coordinates accepted → Spoofing
////////////////////////////////////////////////////////////////////////////////
contract WGSVuln {
    struct Coord { int256 lat; int256 lon; }
    mapping(WGSSystemType => Coord) public coordinates;

    event CoordinatesSet(
        address indexed who,
        WGSSystemType    sysType,
        int256           lat,
        int256           lon,
        WGSSAttackType   attack
    );

    function setCoordinates(
        WGSSystemType sysType,
        int256 lat,
        int256 lon
    ) external {
        coordinates[sysType] = Coord(lat, lon);
        emit CoordinatesSet(msg.sender, sysType, lat, lon, WGSSAttackType.Spoofing);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates spoofing, capture-and-replay, jamming
////////////////////////////////////////////////////////////////////////////////
contract Attack_WGS {
    WGSVuln public target;
    WGSSystemType public lastSys;
    int256 public lastLat;
    int256 public lastLon;

    constructor(WGSVuln _t) { target = _t; }

    function spoof(
        WGSSystemType sysType,
        int256 lat,
        int256 lon
    ) external {
        target.setCoordinates(sysType, lat, lon);
        lastSys = sysType;
        lastLat = lat;
        lastLon = lon;
    }

    function jam(WGSSystemType sysType) external {
        // simulate jamming by setting zeros
        target.setCoordinates(sysType, 0, 0);
    }

    function replay() external {
        target.setCoordinates(lastSys, lastLat, lastLon);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH SIGNATURE VALIDATION
//    • ✅ Defense: SignatureValidation – require signer approval
////////////////////////////////////////////////////////////////////////////////
contract WGSSafeSignature {
    address public signer;
    struct Coord { int256 lat; int256 lon; }
    mapping(WGSSystemType => Coord) public coordinates;

    event CoordinatesSet(
        address indexed who,
        WGSSystemType    sysType,
        int256           lat,
        int256           lon,
        WGSDefenseType   defense
    );

    constructor(address _signer) {
        signer = _signer;
    }

    function setCoordinates(
        WGSSystemType sysType,
        int256 lat,
        int256 lon,
        bytes calldata sig
    ) external {
        bytes32 h = keccak256(abi.encodePacked(sysType, lat, lon));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert WGS__InvalidSignature();
        coordinates[sysType] = Coord(lat, lon);
        emit CoordinatesSet(msg.sender, sysType, lat, lon, WGSDefenseType.SignatureValidation);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH MULTI-SOURCE CONSENSUS
//    • ✅ Defense: MultiSource – require ≥2 reports before accept
////////////////////////////////////////////////////////////////////////////////
contract WGSSafeMultiSource {
    struct Coord { int256 lat; int256 lon; bool committed; }
    mapping(bytes32 => mapping(address => bool)) public reported;
    mapping(bytes32 => uint256) public reportCount;
    mapping(WGSSystemType => Coord) public coordinates;
    uint256 public constant THRESHOLD = 2;

    event CoordinatesCommitted(
        WGSSystemType    sysType,
        int256           lat,
        int256           lon,
        WGSDefenseType   defense
    );

    function reportCoordinates(
        WGSSystemType sysType,
        int256 lat,
        int256 lon
    ) external {
        bytes32 key = keccak256(abi.encodePacked(sysType, lat, lon));
        if (!reported[key][msg.sender]) {
            reported[key][msg.sender] = true;
            reportCount[key]++;
            if (reportCount[key] == THRESHOLD) {
                coordinates[sysType] = Coord(lat, lon, true);
                emit CoordinatesCommitted(sysType, lat, lon, WGSDefenseType.MultiSource);
            }
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH TIMESTAMP VALIDATION & RATE LIMIT
//    • ✅ Defense: TimestampValidation – require recent signed timestamp  
//               RateLimit – cap calls per block
////////////////////////////////////////////////////////////////////////////////
contract WGSSafeAdvanced {
    address public signer;
    struct Coord { int256 lat; int256 lon; }
    mapping(WGSSystemType => Coord) public coordinates;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    mapping(bytes32 => bool) public seen;      // for replay guard
    uint256 public constant MAX_CALLS = 5;
    uint256 public constant MAX_AGE = 5 minutes;

    event CoordinatesSet(
        address indexed who,
        WGSSystemType    sysType,
        int256           lat,
        int256           lon,
        WGSDefenseType   defense
    );

    error WGS__InvalidSignature();
    error WGS__TooManyRequests();
    error WGS__InvalidTimestamp();
    error WGS__AlreadyReported();

    constructor(address _signer) {
        signer = _signer;
    }

    function setCoordinates(
        WGSSystemType sysType,
        int256 lat,
        int256 lon,
        uint256 timestamp,
        bytes32 nonce,
        bytes calldata sig
    ) external {
        // rate-limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert WGS__TooManyRequests<>();

        // timestamp freshness
        if (block.timestamp < timestamp || block.timestamp > timestamp + MAX_AGE)
            revert WGS__InvalidTimestamp();

        // replay guard
        bytes32 key = keccak256(abi.encodePacked(sysType, lat, lon, timestamp, nonce));
        if (seen[key]) revert WGS__AlreadyReported();
        seen[key] = true;

        // signature check
        bytes32 h = keccak256(abi.encodePacked(sysType, lat, lon, timestamp, nonce));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert WGS__InvalidSignature();

        coordinates[sysType] = Coord(lat, lon);
        emit CoordinatesSet(msg.sender, sysType, lat, lon, WGSDefenseType.TimestampValidation);
    }
}
