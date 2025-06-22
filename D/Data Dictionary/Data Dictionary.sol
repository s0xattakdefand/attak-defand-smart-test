// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DataDictionarySecuritySuite.sol
/// @notice On‐chain analogues for “Data Dictionary” security patterns:
///   Types: Logical, Relational, Hierarchical, KeyValue  
///   AttackTypes: UnauthorizedModification, DataPoisoning, Tampering, Injection, Replay  
///   DefenseTypes: AccessControl, IntegrityCheck, RateLimit, SignatureValidation, AuditLogging

enum DataDictionaryType   { Logical, Relational, Hierarchical, KeyValue }
enum DDAttackType         { UnauthorizedModification, DataPoisoning, Tampering, Injection, Replay }
enum DDDefenseType        { AccessControl, IntegrityCheck, RateLimit, SignatureValidation, AuditLogging }

error DD__NotAuthorized();
error DD__InvalidInput();
error DD__TooManyRequests();
error DD__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE DICTIONARY MANAGER
//    • ❌ no checks: anyone may add/update/read entries → Tampering/Injection
////////////////////////////////////////////////////////////////////////////////
contract DataDictionaryVuln {
    mapping(string => string) public definitions;

    event EntryAdded(
        address indexed who,
        string           key,
        string           value,
        DataDictionaryType dtype,
        DDAttackType     attack
    );
    event EntryUpdated(
        address indexed who,
        string           key,
        string           value,
        DataDictionaryType dtype,
        DDAttackType     attack
    );
    event EntryRead(
        address indexed who,
        string           key,
        DataDictionaryType dtype,
        DDAttackType     attack
    );

    function addEntry(string calldata key, string calldata value, DataDictionaryType dtype) external {
        definitions[key] = value;
        emit EntryAdded(msg.sender, key, value, dtype, DDAttackType.UnauthorizedModification);
    }

    function updateEntry(string calldata key, string calldata value, DataDictionaryType dtype) external {
        definitions[key] = value;
        emit EntryUpdated(msg.sender, key, value, dtype, DDAttackType.Tampering);
    }

    function readEntry(string calldata key, DataDictionaryType dtype) external view returns (string memory) {
        emit EntryRead(msg.sender, key, dtype, DDAttackType.Replay);
        return definitions[key];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates unauthorized add/update, data poisoning, replay, injection
////////////////////////////////////////////////////////////////////////////////
contract Attack_DataDictionary {
    DataDictionaryVuln public target;
    string public lastKey;
    string public lastValue;

    constructor(DataDictionaryVuln _t) { target = _t; }

    function spoofAdd(string calldata key, string calldata fake) external {
        target.addEntry(key, fake, DataDictionaryType.Logical);
        lastKey = key;
        lastValue = fake;
    }

    function poisonData(string calldata key, string calldata fake) external {
        target.updateEntry(key, fake, DataDictionaryType.Relational);
    }

    function replayRead() external {
        target.readEntry(lastKey, DataDictionaryType.Hierarchical);
    }

    function injectOverflow(string calldata key) external {
        // simulate injection by very large value
        string memory big = new string(1024);
        target.addEntry(key, big, DataDictionaryType.KeyValue);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may add/update/read
////////////////////////////////////////////////////////////////////////////////
contract DataDictionarySafeAccess {
    mapping(string => string) public definitions;
    address public owner;

    event EntryAdded(
        address indexed who,
        string           key,
        DataDictionaryType dtype,
        DDDefenseType    defense
    );
    event EntryUpdated(
        address indexed who,
        string           key,
        DataDictionaryType dtype,
        DDDefenseType    defense
    );
    event EntryRead(
        address indexed who,
        string           key,
        DataDictionaryType dtype,
        DDDefenseType    defense
    );

    constructor() { owner = msg.sender; }

    modifier onlyOwner() {
        if (msg.sender != owner) revert DD__NotAuthorized();
        _;
    }

    function addEntry(string calldata key, string calldata value, DataDictionaryType dtype)
        external onlyOwner
    {
        definitions[key] = value;
        emit EntryAdded(msg.sender, key, dtype, DDDefenseType.AccessControl);
    }

    function updateEntry(string calldata key, string calldata value, DataDictionaryType dtype)
        external onlyOwner
    {
        definitions[key] = value;
        emit EntryUpdated(msg.sender, key, dtype, DDDefenseType.AccessControl);
    }

    function readEntry(string calldata key, DataDictionaryType dtype)
        external view onlyOwner returns (string memory)
    {
        emit EntryRead(msg.sender, key, dtype, DDDefenseType.AccessControl);
        return definitions[key];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH INTEGRITY CHECK & RATE LIMIT
//    • ✅ Defense: IntegrityCheck – require nonempty value  
//               RateLimit       – cap operations per block
////////////////////////////////////////////////////////////////////////////////
contract DataDictionarySafeValidate {
    mapping(string => string) public definitions;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public opsInBlock;
    uint256 public constant MAX_OPS = 5;

    event EntryAdded(
        address indexed who,
        string           key,
        DataDictionaryType dtype,
        DDDefenseType    defense
    );
    event EntryUpdated(
        address indexed who,
        string           key,
        DataDictionaryType dtype,
        DDDefenseType    defense
    );
    event EntryRead(
        address indexed who,
        string           key,
        DataDictionaryType dtype,
        DDDefenseType    defense
    );

    error DD__InvalidInput();
    error DD__TooManyRequests();

    modifier rateLimit() {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]   = block.number;
            opsInBlock[msg.sender]  = 0;
        }
        opsInBlock[msg.sender]++;
        if (opsInBlock[msg.sender] > MAX_OPS) revert DD__TooManyRequests();
        _;
    }

    function addEntry(string calldata key, string calldata value, DataDictionaryType dtype)
        external rateLimit
    {
        if (bytes(value).length == 0) revert DD__InvalidInput();
        definitions[key] = value;
        emit EntryAdded(msg.sender, key, dtype, DDDefenseType.IntegrityCheck);
    }

    function updateEntry(string calldata key, string calldata value, DataDictionaryType dtype)
        external rateLimit
    {
        if (bytes(value).length == 0) revert DD__InvalidInput();
        definitions[key] = value;
        emit EntryUpdated(msg.sender, key, dtype, DDDefenseType.IntegrityCheck);
    }

    function readEntry(string calldata key, DataDictionaryType dtype)
        external rateLimit returns (string memory)
    {
        string memory v = definitions[key];
        emit EntryRead(msg.sender, key, dtype, DDDefenseType.RateLimit);
        return v;
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & AUDIT LOGGING
//    • ✅ Defense: SignatureValidation – require admin‐signed ops  
//               AuditLogging      – record each action
////////////////////////////////////////////////////////////////////////////////
contract DataDictionarySafeAdvanced {
    mapping(string => string) public definitions;
    address public signer;

    event EntryAdded(
        address indexed who,
        string           key,
        DataDictionaryType dtype,
        DDDefenseType    defense
    );
    event EntryUpdated(
        address indexed who,
        string           key,
        DataDictionaryType dtype,
        DDDefenseType    defense
    );
    event EntryRead(
        address indexed who,
        string           key,
        DataDictionaryType dtype,
        DDDefenseType    defense
    );
    event AuditLog(
        address indexed who,
        string           action,
        string           key,
        DDDefenseType    defense
    );

    error DD__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function addEntry(
        string calldata key,
        string calldata value,
        DataDictionaryType dtype,
        bytes calldata sig
    ) external {
        bytes32 h = keccak256(abi.encodePacked("ADD", msg.sender, key, value, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DD__InvalidSignature();

        definitions[key] = value;
        emit EntryAdded(msg.sender, key, dtype, DDDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "addEntry", key, DDDefenseType.AuditLogging);
    }

    function updateEntry(
        string calldata key,
        string calldata value,
        DataDictionaryType dtype,
        bytes calldata sig
    ) external {
        bytes32 h = keccak256(abi.encodePacked("UPDATE", msg.sender, key, value, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DD__InvalidSignature();

        definitions[key] = value;
        emit EntryUpdated(msg.sender, key, dtype, DDDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "updateEntry", key, DDDefenseType.AuditLogging);
    }

    function readEntry(
        string calldata key,
        DataDictionaryType dtype,
        bytes calldata sig
    ) external returns (string memory) {
        bytes32 h = keccak256(abi.encodePacked("READ", msg.sender, key, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DD__InvalidSignature();

        string memory v = definitions[key];
        emit EntryRead(msg.sender, key, dtype, DDDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "readEntry", key, DDDefenseType.AuditLogging);
        return v;
    }
}
