// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DataConsumerSecuritySuite.sol
/// @notice On‐chain analogues for “Data Consumer” security patterns:
///   Types: SimpleConsumer, BatchConsumer, PermissionedConsumer, StreamingConsumer  
///   AttackTypes: UnauthorizedConsume, DataTampering, ReplayConsume, FloodConsume  
///   DefenseTypes: AccessControl, IntegrityCheck, RateLimit, SignatureValidation, AuditLogging

enum DCSType             { SimpleConsumer, BatchConsumer, PermissionedConsumer, StreamingConsumer }
enum DCAttackType        { UnauthorizedConsume, DataTampering, ReplayConsume, FloodConsume }
enum DCDefenseType       { AccessControl, IntegrityCheck, RateLimit, SignatureValidation, AuditLogging }

error DC__NotAuthorized();
error DC__InvalidInput();
error DC__TooManyRequests();
error DC__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE DATA CONSUMER
//    • ❌ no checks: anyone may consume or tamper data → UnauthorizedConsume/DataTampering
////////////////////////////////////////////////////////////////////////////////
contract DataConsumerVuln {
    mapping(uint256 => string) public dataStore;

    event DataConsumed(
        address indexed who,
        uint256           id,
        DCSType           dtype,
        DCAttackType      attack
    );
    event DataTampered(
        address indexed who,
        uint256           id,
        DCSType           dtype,
        DCAttackType      attack
    );

    function consume(uint256 id, DCSType dtype) external view returns (string memory) {
        emit DataConsumed(msg.sender, id, dtype, DCAttackType.UnauthorizedConsume);
        return dataStore[id];
    }

    function tamper(uint256 id, string calldata newData, DCSType dtype) external {
        dataStore[id] = newData;
        emit DataTampered(msg.sender, id, dtype, DCAttackType.DataTampering);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates unauthorized consume, tamper, replay, flood
////////////////////////////////////////////////////////////////////////////////
contract Attack_DataConsumer {
    DataConsumerVuln public target;
    uint256 public lastId;
    string  public lastData;

    constructor(DataConsumerVuln _t) {
        target = _t;
    }

    function unauthorizedConsume(uint256 id) external {
        lastData = target.consume(id, DCSType.SimpleConsumer);
        lastId = id;
    }

    function tamper(uint256 id, string calldata fake) external {
        target.tamper(id, fake, DCSType.PermissionedConsumer);
    }

    function replayConsume() external {
        target.consume(lastId, DCSType.BatchConsumer);
    }

    function floodConsume(uint256 id, uint256 times) external {
        for (uint i = 0; i < times; i++) {
            target.consume(id, DCSType.StreamingConsumer);
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may consume or tamper
////////////////////////////////////////////////////////////////////////////////
contract DataConsumerSafeAccess {
    mapping(uint256 => string) public dataStore;
    address public owner;

    event DataConsumed(
        address indexed who,
        uint256           id,
        DCSType           dtype,
        DCDefenseType     defense
    );
    event DataTampered(
        address indexed who,
        uint256           id,
        DCSType           dtype,
        DCDefenseType     defense
    );

    constructor() {
        owner = msg.sender;
    }
    modifier onlyOwner() {
        if (msg.sender != owner) revert DC__NotAuthorized();
        _;
    }

    function consume(uint256 id, DCSType dtype) external view onlyOwner returns (string memory) {
        emit DataConsumed(msg.sender, id, dtype, DCDefenseType.AccessControl);
        return dataStore[id];
    }

    function tamper(uint256 id, string calldata newData, DCSType dtype) external onlyOwner {
        dataStore[id] = newData;
        emit DataTampered(msg.sender, id, dtype, DCDefenseType.AccessControl);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH INTEGRITY CHECK & RATE LIMIT
//    • ✅ Defense: IntegrityCheck – require nonempty data  
//               RateLimit       – cap ops per block
////////////////////////////////////////////////////////////////////////////////
contract DataConsumerSafeValidate {
    mapping(uint256 => string) public dataStore;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public opsInBlock;
    uint256 public constant MAX_OPS = 5;

    event DataConsumed(
        address indexed who,
        uint256           id,
        DCSType           dtype,
        DCDefenseType     defense
    );
    event DataTampered(
        address indexed who,
        uint256           id,
        DCSType           dtype,
        DCDefenseType     defense
    );

    error DC__InvalidInput();
    error DC__TooManyRequests();

    modifier rateLimit() {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]   = block.number;
            opsInBlock[msg.sender] = 0;
        }
        opsInBlock[msg.sender]++;
        if (opsInBlock[msg.sender] > MAX_OPS) revert DC__TooManyRequests();
        _;
    }

    function consume(uint256 id, DCSType dtype) external view rateLimit returns (string memory) {
        emit DataConsumed(msg.sender, id, dtype, DCDefenseType.RateLimit);
        return dataStore[id];
    }

    function tamper(uint256 id, string calldata newData, DCSType dtype) external rateLimit {
        if (bytes(newData).length == 0) revert DC__InvalidInput();
        dataStore[id] = newData;
        emit DataTampered(msg.sender, id, dtype, DCDefenseType.IntegrityCheck);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & AUDIT LOGGING
//    • ✅ Defense: SignatureValidation – require admin‐signed ops  
//               AuditLogging      – record each action
////////////////////////////////////////////////////////////////////////////////
contract DataConsumerSafeAdvanced {
    mapping(uint256 => string) public dataStore;
    address public signer;

    event DataConsumed(
        address indexed who,
        uint256           id,
        DCSType           dtype,
        DCDefenseType     defense
    );
    event DataTampered(
        address indexed who,
        uint256           id,
        DCSType           dtype,
        DCDefenseType     defense
    );
    event AuditLog(
        address indexed who,
        string            action,
        uint256           id,
        DCDefenseType     defense
    );

    error DC__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function consume(
        uint256 id,
        DCSType dtype,
        bytes calldata sig
    ) external returns (string memory) {
        // verify signature over (msg.sender||id||dtype||"consume")
        bytes32 h = keccak256(abi.encodePacked(msg.sender, id, dtype, "consume"));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DC__InvalidSignature();

        string memory d = dataStore[id];
        emit DataConsumed(msg.sender, id, dtype, DCDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "consume", id, DCDefenseType.AuditLogging);
        return d;
    }

    function tamper(
        uint256 id,
        string calldata newData,
        DCSType dtype,
        bytes calldata sig
    ) external {
        // verify signature over (msg.sender||id||newData||dtype)
        bytes32 h = keccak256(abi.encodePacked(msg.sender, id, newData, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DC__InvalidSignature();

        dataStore[id] = newData;
        emit DataTampered(msg.sender, id, dtype, DCDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "tamper", id, DCDefenseType.AuditLogging);
    }
}
