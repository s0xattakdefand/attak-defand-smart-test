// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DataHistorianSecuritySuite.sol
/// @notice On‐chain analogues for “Data Historian” security patterns:
///   Types: SimpleHistorian, TemporalHistorian, ImmutableHistorian, VersionedHistorian  
///   AttackTypes: UnauthorizedLog, DataPoisoning, ReplayHistory, FloodLog  
///   DefenseTypes: AccessControl, IntegrityCheck, RateLimit, SignatureValidation, AuditLogging

enum DHType               { SimpleHistorian, TemporalHistorian, ImmutableHistorian, VersionedHistorian }
enum DHAttackType         { UnauthorizedLog, DataPoisoning, ReplayHistory, FloodLog }
enum DHDefenseType        { AccessControl, IntegrityCheck, RateLimit, SignatureValidation, AuditLogging }

error DH__NotAuthorized();
error DH__InvalidInput();
error DH__TooManyRequests();
error DH__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE HISTORIAN
//    • ❌ no checks: anyone may log or read history → UnauthorizedLog/DataPoisoning
////////////////////////////////////////////////////////////////////////////////
contract DataHistorianVuln {
    mapping(uint256 => string) public records;

    event LogAdded(
        address indexed who,
        uint256           id,
        DHType            dtype,
        DHAttackType      attack
    );
    event LogRead(
        address indexed who,
        uint256           id,
        DHType            dtype,
        DHAttackType      attack
    );

    function logEntry(uint256 id, string calldata data, DHType dtype) external {
        records[id] = data;
        emit LogAdded(msg.sender, id, dtype, DHAttackType.UnauthorizedLog);
    }

    function readEntry(uint256 id, DHType dtype) external view returns (string memory) {
        emit LogRead(msg.sender, id, dtype, DHAttackType.ReplayHistory);
        return records[id];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates spoofed logs, tampering, replay, flood
////////////////////////////////////////////////////////////////////////////////
contract Attack_DataHistorian {
    DataHistorianVuln public target;
    uint256 public lastId;
    string  public lastData;

    constructor(DataHistorianVuln _t) {
        target = _t;
    }

    function spoofLog(uint256 id, string calldata fake) external {
        target.logEntry(id, fake, DHType.SimpleHistorian);
        lastId   = id;
        lastData = fake;
    }

    function poisonLog(uint256 id, string calldata fake) external {
        target.logEntry(id, fake, DHType.ImmutableHistorian);
    }

    function replayLog() external {
        target.logEntry(lastId, lastData, DHType.TemporalHistorian);
    }

    function floodLogs(uint256 id, uint256 times) external {
        for (uint i = 0; i < times; i++) {
            target.logEntry(id, "flood", DHType.VersionedHistorian);
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may log or read
////////////////////////////////////////////////////////////////////////////////
contract DataHistorianSafeAccess {
    mapping(uint256 => string) public records;
    address public owner;

    event LogAdded(
        address indexed who,
        uint256           id,
        DHType            dtype,
        DHDefenseType     defense
    );
    event LogRead(
        address indexed who,
        uint256           id,
        DHType            dtype,
        DHDefenseType     defense
    );

    constructor() {
        owner = msg.sender;
    }
    modifier onlyOwner() {
        if (msg.sender != owner) revert DH__NotAuthorized();
        _;
    }

    function logEntry(uint256 id, string calldata data, DHType dtype) external onlyOwner {
        records[id] = data;
        emit LogAdded(msg.sender, id, dtype, DHDefenseType.AccessControl);
    }

    function readEntry(uint256 id, DHType dtype) external view onlyOwner returns (string memory) {
        emit LogRead(msg.sender, id, dtype, DHDefenseType.AccessControl);
        return records[id];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH INTEGRITY CHECK & RATE LIMIT
//    • ✅ Defense: IntegrityCheck – require nonempty data  
//               RateLimit       – cap ops per block
////////////////////////////////////////////////////////////////////////////////
contract DataHistorianSafeValidate {
    mapping(uint256 => string) public records;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public opsInBlock;
    uint256 public constant MAX_OPS = 5;

    event LogAdded(
        address indexed who,
        uint256           id,
        DHType            dtype,
        DHDefenseType     defense
    );
    event LogRead(
        address indexed who,
        uint256           id,
        DHType            dtype,
        DHDefenseType     defense
    );

    error DH__InvalidInput();
    error DH__TooManyRequests();

    modifier rateLimit() {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]   = block.number;
            opsInBlock[msg.sender]  = 0;
        }
        opsInBlock[msg.sender]++;
        if (opsInBlock[msg.sender] > MAX_OPS) revert DH__TooManyRequests();
        _;
    }

    function logEntry(uint256 id, string calldata data, DHType dtype) external rateLimit {
        if (bytes(data).length == 0) revert DH__InvalidInput();
        records[id] = data;
        emit LogAdded(msg.sender, id, dtype, DHDefenseType.IntegrityCheck);
    }

    function readEntry(uint256 id, DHType dtype) external rateLimit returns (string memory) {
        emit LogRead(msg.sender, id, dtype, DHDefenseType.RateLimit);
        return records[id];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & AUDIT LOGGING
//    • ✅ Defense: SignatureValidation – require admin‐signed ops  
//               AuditLogging      – record each action
////////////////////////////////////////////////////////////////////////////////
contract DataHistorianSafeAdvanced {
    mapping(uint256 => string) public records;
    address public signer;

    event LogAdded(
        address indexed who,
        uint256           id,
        DHType            dtype,
        DHDefenseType     defense
    );
    event LogRead(
        address indexed who,
        uint256           id,
        DHType            dtype,
        DHDefenseType     defense
    );
    event AuditLog(
        address indexed who,
        string            action,
        uint256           id,
        DHDefenseType     defense
    );

    error DH__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function logEntry(
        uint256 id,
        string calldata data,
        DHType dtype,
        bytes calldata sig
    ) external {
        bytes32 h = keccak256(abi.encodePacked("LOG", msg.sender, id, data, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DH__InvalidSignature();

        records[id] = data;
        emit LogAdded(msg.sender, id, dtype, DHDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "logEntry", id, DHDefenseType.AuditLogging);
    }

    function readEntry(
        uint256 id,
        DHType dtype,
        bytes calldata sig
    ) external returns (string memory) {
        bytes32 h = keccak256(abi.encodePacked("READ", msg.sender, id, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DH__InvalidSignature();

        string memory data = records[id];
        emit LogRead(msg.sender, id, dtype, DHDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "readEntry", id, DHDefenseType.AuditLogging);
        return data;
    }
}
