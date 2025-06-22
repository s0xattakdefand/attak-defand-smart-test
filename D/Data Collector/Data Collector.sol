// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DataCollectorSecuritySuite.sol
/// @notice On‐chain analogues for “Data Collector” security patterns:
///   Types: SimpleCollector, BatchedCollector, PermissionedCollector, RealTimeCollector  
///   AttackTypes: UnauthorizedCollection, DataTampering, ReplayAttack, FloodAttack  
///   DefenseTypes: AccessControl, IntegrityCheck, RateLimit, SignatureValidation, AuditLogging

enum DCType               { SimpleCollector, BatchedCollector, PermissionedCollector, RealTimeCollector }
enum DCAttackType         { UnauthorizedCollection, DataTampering, ReplayAttack, FloodAttack }
enum DCDefenseType        { AccessControl, IntegrityCheck, RateLimit, SignatureValidation, AuditLogging }

error DC__NotAuthorized();
error DC__InvalidInput();
error DC__TooManyRequests();
error DC__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE DATA COLLECTOR
//    • ❌ no checks: anyone may collect, update, or read data → UnauthorizedCollection, DataTampering
////////////////////////////////////////////////////////////////////////////////
contract DataCollectorVuln {
    mapping(uint256 => string) public collected;

    event DataCollected(
        address indexed who,
        uint256 indexed id,
        DCType    dtype,
        DCAttackType attack
    );
    event DataUpdated(
        address indexed who,
        uint256 indexed id,
        DCType    dtype,
        DCAttackType attack
    );
    event DataRead(
        address indexed who,
        uint256 indexed id,
        DCType    dtype,
        DCAttackType attack
    );

    function collectData(uint256 id, string calldata data, DCType dtype) external {
        collected[id] = data;
        emit DataCollected(msg.sender, id, dtype, DCAttackType.UnauthorizedCollection);
    }

    function updateData(uint256 id, string calldata data, DCType dtype) external {
        collected[id] = data;
        emit DataUpdated(msg.sender, id, dtype, DCAttackType.DataTampering);
    }

    function readData(uint256 id, DCType dtype) external view returns (string memory) {
        emit DataRead(msg.sender, id, dtype, DCAttackType.ReplayAttack);
        return collected[id];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates unauthorized collect, tamper, replay, flood
////////////////////////////////////////////////////////////////////////////////
contract Attack_DataCollector {
    DataCollectorVuln public target;
    uint256 public lastId;
    string  public lastData;

    constructor(DataCollectorVuln _t) {
        target = _t;
    }

    function spoofCollect(uint256 id, string calldata fake) external {
        target.collectData(id, fake, DCType.SimpleCollector);
        lastId   = id;
        lastData = fake;
    }

    function tamper(uint256 id, string calldata fake) external {
        target.updateData(id, fake, DCType.PermissionedCollector);
    }

    function leak(uint256 id) external {
        lastData = target.readData(id, DCType.BatchedCollector);
    }

    function replayCollect() external {
        target.collectData(lastId, lastData, DCType.RealTimeCollector);
    }

    function floodRead(uint256 id, uint256 times) external {
        for (uint i = 0; i < times; i++) {
            target.readData(id, DCType.RealTimeCollector);
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may collect/update/read
////////////////////////////////////////////////////////////////////////////////
contract DataCollectorSafeAccess {
    mapping(uint256 => string) public collected;
    address public owner;

    event DataCollected(
        address indexed who,
        uint256 indexed id,
        DCType    dtype,
        DCDefenseType defense
    );
    event DataUpdated(
        address indexed who,
        uint256 indexed id,
        DCType    dtype,
        DCDefenseType defense
    );
    event DataRead(
        address indexed who,
        uint256 indexed id,
        DCType    dtype,
        DCDefenseType defense
    );

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert DC__NotAuthorized();
        _;
    }

    function collectData(uint256 id, string calldata data, DCType dtype) external onlyOwner {
        collected[id] = data;
        emit DataCollected(msg.sender, id, dtype, DCDefenseType.AccessControl);
    }

    function updateData(uint256 id, string calldata data, DCType dtype) external onlyOwner {
        collected[id] = data;
        emit DataUpdated(msg.sender, id, dtype, DCDefenseType.AccessControl);
    }

    function readData(uint256 id, DCType dtype) external view onlyOwner returns (string memory) {
        emit DataRead(msg.sender, id, dtype, DCDefenseType.AccessControl);
        return collected[id];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH VALIDATION & RATE LIMIT
//    • ✅ Defense: IntegrityCheck – require nonempty data  
//               RateLimit       – cap operations per block
////////////////////////////////////////////////////////////////////////////////
contract DataCollectorSafeValidate {
    mapping(uint256 => string) public collected;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public opsInBlock;
    uint256 public constant MAX_OPS = 5;

    event DataCollected(
        address indexed who,
        uint256 indexed id,
        DCType    dtype,
        DCDefenseType defense
    );
    event DataUpdated(
        address indexed who,
        uint256 indexed id,
        DCType    dtype,
        DCDefenseType defense
    );
    event DataRead(
        address indexed who,
        uint256 indexed id,
        DCType    dtype,
        DCDefenseType defense
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

    function collectData(uint256 id, string calldata data, DCType dtype) external rateLimit {
        if (bytes(data).length == 0) revert DC__InvalidInput();
        collected[id] = data;
        emit DataCollected(msg.sender, id, dtype, DCDefenseType.IntegrityCheck);
    }

    function updateData(uint256 id, string calldata data, DCType dtype) external rateLimit {
        if (bytes(data).length == 0) revert DC__InvalidInput();
        collected[id] = data;
        emit DataUpdated(msg.sender, id, dtype, DCDefenseType.IntegrityCheck);
    }

    function readData(uint256 id, DCType dtype) external rateLimit returns (string memory) {
        emit DataRead(msg.sender, id, dtype, DCDefenseType.RateLimit);
        return collected[id];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & AUDIT LOGGING
//    • ✅ Defense: SignatureValidation – require admin‐signed ops  
//               AuditLogging      – record each action
////////////////////////////////////////////////////////////////////////////////
contract DataCollectorSafeAdvanced {
    mapping(uint256 => string) public collected;
    address public signer;

    event DataCollected(
        address indexed who,
        uint256 indexed id,
        DCType    dtype,
        DCDefenseType defense
    );
    event DataUpdated(
        address indexed who,
        uint256 indexed id,
        DCType    dtype,
        DCDefenseType defense
    );
    event DataRead(
        address indexed who,
        uint256 indexed id,
        DCType    dtype,
        DCDefenseType defense
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

    function collectData(
        uint256 id,
        string calldata data,
        DCType dtype,
        bytes calldata sig
    ) external {
        // verify signature over (msg.sender||id||data||dtype)
        bytes32 h = keccak256(abi.encodePacked(msg.sender, id, data, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DC__InvalidSignature();

        collected[id] = data;
        emit DataCollected(msg.sender, id, dtype, DCDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "collectData", id, DCDefenseType.AuditLogging);
    }

    function updateData(
        uint256 id,
        string calldata data,
        DCType dtype,
        bytes calldata sig
    ) external {
        bytes32 h = keccak256(abi.encodePacked(msg.sender, id, data, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DC__InvalidSignature();

        collected[id] = data;
        emit DataUpdated(msg.sender, id, dtype, DCDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "updateData", id, DCDefenseType.AuditLogging);
    }

    function readData(
        uint256 id,
        DCType dtype,
        bytes calldata sig
    ) external returns (string memory) {
        bytes32 h = keccak256(abi.encodePacked(msg.sender, id, dtype, "read"));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DC__InvalidSignature();

        string memory data = collected[id];
        emit DataRead(msg.sender, id, dtype, DCDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "readData", id, DCDefenseType.AuditLogging);
        return data;
    }
}
