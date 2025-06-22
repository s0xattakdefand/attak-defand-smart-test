// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DataDictionaryEntrySecuritySuite.sol
/// @notice On‐chain analogues for “Data Dictionary Entry” security patterns:
///   Types: Logical, Relational, Hierarchical, KeyValue  
///   AttackTypes: UnauthorizedModification, DataPoisoning, Replay, Injection  
///   DefenseTypes: AccessControl, IntegrityCheck, RateLimit, SignatureValidation, AuditLogging

enum DDEType             { Logical, Relational, Hierarchical, KeyValue }
enum DDEAttackType       { UnauthorizedModification, DataPoisoning, Replay, Injection }
enum DDEDefenseType      { AccessControl, IntegrityCheck, RateLimit, SignatureValidation, AuditLogging }

error DDE__NotAuthorized();
error DDE__InvalidInput();
error DDE__TooManyRequests();
error DDE__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE DICTIONARY ENTRY MANAGER
//    • ❌ no checks: anyone may add/update/read → UnauthorizedModification/DataPoisoning
////////////////////////////////////////////////////////////////////////////////
contract DDEVuln {
    struct Entry { string key; string value; }
    mapping(uint256 => Entry) public entries;

    event EntryAdded(
        address indexed who,
        uint256           entryId,
        string            key,
        string            value,
        DDEType           dtype,
        DDEAttackType     attack
    );
    event EntryUpdated(
        address indexed who,
        uint256           entryId,
        string            key,
        string            value,
        DDEType           dtype,
        DDEAttackType     attack
    );
    event EntryRead(
        address indexed who,
        uint256           entryId,
        DDEType           dtype,
        DDEAttackType     attack
    );

    function addEntry(
        uint256 entryId,
        string calldata key,
        string calldata value,
        DDEType dtype
    ) external {
        entries[entryId] = Entry(key, value);
        emit EntryAdded(msg.sender, entryId, key, value, dtype, DDEAttackType.UnauthorizedModification);
    }

    function updateEntry(
        uint256 entryId,
        string calldata key,
        string calldata value,
        DDEType dtype
    ) external {
        entries[entryId] = Entry(key, value);
        emit EntryUpdated(msg.sender, entryId, key, value, dtype, DDEAttackType.DataPoisoning);
    }

    function readEntry(
        uint256 entryId,
        DDEType dtype
    ) external view returns (string memory key, string memory value) {
        Entry storage e = entries[entryId];
        emit EntryRead(msg.sender, entryId, dtype, DDEAttackType.Replay);
        return (e.key, e.value);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates unauthorized add, poisoning, replay, injection
////////////////////////////////////////////////////////////////////////////////
contract Attack_DataDictionaryEntry {
    DDEVuln public target;
    uint256 public lastId;
    string  public lastKey;
    string  public lastValue;

    constructor(DDEVuln _t) { target = _t; }

    function spoofAdd(uint256 id, string calldata key, string calldata val) external {
        target.addEntry(id, key, val, DDEType.Logical);
        lastId = id;
        lastKey = key;
        lastValue = val;
    }

    function poison(uint256 id, string calldata key, string calldata val) external {
        target.updateEntry(id, key, val, DDEType.Relational);
    }

    function replayAdd() external {
        target.addEntry(lastId, lastKey, lastValue, DDEType.Hierarchical);
    }

    function inject(uint256 id) external {
        // simulate injection with large value
        string memory big = new string(512);
        target.addEntry(id, "injection", big, DDEType.KeyValue);
    }

    function floodRead(uint256 id, uint256 times) external {
        for (uint i = 0; i < times; ++i) {
            target.readEntry(id, DDEType.Logical);
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may add/update/read
////////////////////////////////////////////////////////////////////////////////
contract DDESafeAccess {
    struct Entry { string key; string value; }
    mapping(uint256 => Entry) public entries;
    address public owner;

    event EntryAdded(
        address indexed who,
        uint256           entryId,
        DDEType           dtype,
        DDEDefenseType    defense
    );
    event EntryUpdated(
        address indexed who,
        uint256           entryId,
        DDEType           dtype,
        DDEDefenseType    defense
    );
    event EntryRead(
        address indexed who,
        uint256           entryId,
        DDEType           dtype,
        DDEDefenseType    defense
    );

    constructor() { owner = msg.sender; }

    modifier onlyOwner() {
        if (msg.sender != owner) revert DDE__NotAuthorized();
        _;
    }

    function addEntry(
        uint256 entryId,
        string calldata key,
        string calldata value,
        DDEType dtype
    ) external onlyOwner {
        entries[entryId] = Entry(key, value);
        emit EntryAdded(msg.sender, entryId, dtype, DDEDefenseType.AccessControl);
    }

    function updateEntry(
        uint256 entryId,
        string calldata key,
        string calldata value,
        DDEType dtype
    ) external onlyOwner {
        entries[entryId] = Entry(key, value);
        emit EntryUpdated(msg.sender, entryId, dtype, DDEDefenseType.AccessControl);
    }

    function readEntry(
        uint256 entryId,
        DDEType dtype
    ) external view onlyOwner returns (string memory key, string memory value) {
        Entry storage e = entries[entryId];
        emit EntryRead(msg.sender, entryId, dtype, DDEDefenseType.AccessControl);
        return (e.key, e.value);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH VALIDATION & RATE LIMIT
//    • ✅ Defense: IntegrityCheck – require nonempty key/value  
//               RateLimit       – cap ops per block
////////////////////////////////////////////////////////////////////////////////
contract DDESafeValidate {
    struct Entry { string key; string value; }
    mapping(uint256 => Entry) public entries;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public opsInBlock;
    uint256 public constant MAX_OPS = 5;

    event EntryAdded(
        address indexed who,
        uint256           entryId,
        DDEType           dtype,
        DDEDefenseType    defense
    );
    event EntryUpdated(
        address indexed who,
        uint256           entryId,
        DDEType           dtype,
        DDEDefenseType    defense
    );
    event EntryRead(
        address indexed who,
        uint256           entryId,
        DDEType           dtype,
        DDEDefenseType    defense
    );

    error DDE__InvalidInput();
    error DDE__TooManyRequests();

    modifier rateLimit() {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]   = block.number;
            opsInBlock[msg.sender]  = 0;
        }
        opsInBlock[msg.sender]++;
        if (opsInBlock[msg.sender] > MAX_OPS) revert DDE__TooManyRequests();
        _;
    }

    function addEntry(
        uint256 entryId,
        string calldata key,
        string calldata value,
        DDEType dtype
    ) external rateLimit {
        if (bytes(key).length == 0 || bytes(value).length == 0) revert DDE__InvalidInput();
        entries[entryId] = Entry(key, value);
        emit EntryAdded(msg.sender, entryId, dtype, DDEDefenseType.IntegrityCheck);
    }

    function updateEntry(
        uint256 entryId,
        string calldata key,
        string calldata value,
        DDEType dtype
    ) external rateLimit {
        if (bytes(key).length == 0 || bytes(value).length == 0) revert DDE__InvalidInput();
        entries[entryId] = Entry(key, value);
        emit EntryUpdated(msg.sender, entryId, dtype, DDEDefenseType.IntegrityCheck);
    }

    function readEntry(
        uint256 entryId,
        DDEType dtype
    ) external rateLimit returns (string memory key, string memory value) {
        Entry storage e = entries[entryId];
        emit EntryRead(msg.sender, entryId, dtype, DDEDefenseType.RateLimit);
        return (e.key, e.value);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & AUDIT LOGGING
//    • ✅ Defense: SignatureValidation – require admin‐signed ops  
//               AuditLogging      – record each action
////////////////////////////////////////////////////////////////////////////////
contract DDESafeAdvanced {
    struct Entry { string key; string value; }
    mapping(uint256 => Entry) public entries;
    address public signer;

    event EntryAdded(
        address indexed who,
        uint256           entryId,
        DDEType           dtype,
        DDEDefenseType    defense
    );
    event EntryUpdated(
        address indexed who,
        uint256           entryId,
        DDEType           dtype,
        DDEDefenseType    defense
    );
    event EntryRead(
        address indexed who,
        uint256           entryId,
        DDEType           dtype,
        DDEDefenseType    defense
    );
    event AuditLog(
        address indexed who,
        string            action,
        uint256           entryId,
        DDEDefenseType    defense
    );

    error DDE__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function addEntry(
        uint256 entryId,
        string calldata key,
        string calldata value,
        DDEType dtype,
        bytes calldata sig
    ) external {
        bytes32 h = keccak256(abi.encodePacked("ADD", msg.sender, entryId, key, value, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DDE__InvalidSignature();

        entries[entryId] = Entry(key, value);
        emit EntryAdded(msg.sender, entryId, dtype, DDEDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "addEntry", entryId, DDEDefenseType.AuditLogging);
    }

    function updateEntry(
        uint256 entryId,
        string calldata key,
        string calldata value,
        DDEType dtype,
        bytes calldata sig
    ) external {
        bytes32 h = keccak256(abi.encodePacked("UPDATE", msg.sender, entryId, key, value, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DDE__InvalidSignature();

        entries[entryId] = Entry(key, value);
        emit EntryUpdated(msg.sender, entryId, dtype, DDEDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "updateEntry", entryId, DDEDefenseType.AuditLogging);
    }

    function readEntry(
        uint256 entryId,
        DDEType dtype,
        bytes calldata sig
    ) external returns (string memory key, string memory value) {
        bytes32 h = keccak256(abi.encodePacked("READ", msg.sender, entryId, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DDE__InvalidSignature();

        Entry storage e = entries[entryId];
        emit EntryRead(msg.sender, entryId, dtype, DDEDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "readEntry", entryId, DDEDefenseType.AuditLogging);
        return (e.key, e.value);
    }
}
