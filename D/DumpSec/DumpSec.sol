// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DumpSecSuite.sol
/// @notice On‑chain analogues of “Dump Sec” data‑dumping patterns:
///   Types: Full, Incremental, Audit  
///   AttackTypes: UnauthorizedDump, Tampering, Replay  
///   DefenseTypes: AccessControl, Encryption, RateLimit, AuditLogging  

enum DumpSecType           { Full, Incremental, Audit }
enum DumpSecAttackType     { UnauthorizedDump, Tampering, Replay }
enum DumpSecDefenseType    { AccessControl, Encryption, RateLimit, AuditLogging }

error DS__NotOwner();
error DS__TooManyRequests();
error DS__Unauthorized();
error DS__InvalidKey();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE DUMP SERVICE
///
///    • no access control, returns any data on dump → UnauthorizedDump
///─────────────────────────────────────────────────────────────────────────────
contract DumpSecVuln {
    mapping(uint256 => bytes) public records;
    event DataDumped(
        address indexed who,
        uint256 indexed id,
        DumpSecType    dtype,
        DumpSecAttackType attack,
        bytes          data
    );

    /// ❌ anyone may store or overwrite data
    function store(uint256 id, bytes calldata data) external {
        records[id] = data;
    }

    /// ❌ anyone may dump any record
    function dump(uint256 id, DumpSecType dtype) external {
        bytes memory d = records[id];
        emit DataDumped(msg.sender, id, dtype, DumpSecAttackType.UnauthorizedDump, d);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB
///
///    • floods dump calls and tampers with stored data
///─────────────────────────────────────────────────────────────────────────────
contract Attack_DumpSec {
    DumpSecVuln public target;
    constructor(DumpSecVuln _t) { target = _t; }

    /// flood dumps to exhaust logs
    function floodDump(uint256 id, DumpSecType dtype, uint256 times) external {
        for (uint256 i = 0; i < times; i++) {
            target.dump(id, dtype);
        }
    }

    /// tamper a record by overwriting
    function tamper(uint256 id, bytes calldata fakeData) external {
        target.store(id, fakeData);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE DUMP WITH ACCESS CONTROL
///
///    • Defense: AccessControl – only owner may dump or store
///─────────────────────────────────────────────────────────────────────────────
contract DumpSecSafe {
    mapping(uint256 => bytes) private records;
    address public owner;

    event DataDumped(
        address indexed who,
        uint256 indexed id,
        DumpSecType    dtype,
        DumpSecDefenseType defense,
        bytes          data
    );

    constructor() {
        owner = msg.sender;
    }

    function store(uint256 id, bytes calldata data) external {
        if (msg.sender != owner) revert DS__NotOwner();
        records[id] = data;
    }

    function dump(uint256 id, DumpSecType dtype) external {
        if (msg.sender != owner) revert DS__NotOwner();
        bytes memory d = records[id];
        emit DataDumped(msg.sender, id, dtype, DumpSecDefenseType.AccessControl, d);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE DUMP WITH RATE‑LIMITING
///
///    • Defense: RateLimit – cap dumps per block per caller
///─────────────────────────────────────────────────────────────────────────────
contract DumpSecSafeRateLimit {
    mapping(uint256 => bytes) private records;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public countInBlock;
    uint256 public constant MAX_PER_BLOCK = 5;
    address public owner;

    event DataDumped(
        address indexed who,
        uint256 indexed id,
        DumpSecType    dtype,
        DumpSecDefenseType defense,
        bytes          data
    );

    error DS__TooManyRequests();
    error DS__NotOwner();

    constructor() {
        owner = msg.sender;
    }

    function store(uint256 id, bytes calldata data) external {
        if (msg.sender != owner) revert DS__NotOwner();
        records[id] = data;
    }

    function dump(uint256 id, DumpSecType dtype) external {
        if (msg.sender != owner) revert DS__NotOwner();
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender]++;
        if (countInBlock[msg.sender] > MAX_PER_BLOCK) revert DS__TooManyRequests();

        bytes memory d = records[id];
        emit DataDumped(msg.sender, id, dtype, DumpSecDefenseType.RateLimit, d);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 5) SAFE ADVANCED DUMP WITH ENCRYPTION & AUDIT LOGGING
///
///    • Defense: Encryption – require caller’s key to decrypt  
///               AuditLogging – emit encrypted dump
///─────────────────────────────────────────────────────────────────────────────
contract DumpSecSafeAdvanced {
    mapping(uint256 => bytes) private records;
    mapping(address => bytes32) public clientKey;
    address public owner;

    event EncryptedDump(
        address indexed who,
        uint256 indexed id,
        DumpSecType    dtype,
        DumpSecDefenseType defense,
        bytes          ciphertext
    );

    error DS__Unauthorized();
    error DS__InvalidKey();

    constructor() {
        owner = msg.sender;
    }

    /// owner stores raw data
    function store(uint256 id, bytes calldata data) external {
        if (msg.sender != owner) revert DS__Unauthorized();
        records[id] = data;
    }

    /// clients register their symmetric key (off‑chain secure setup)
    function registerKey(bytes32 key) external {
        clientKey[msg.sender] = key;
    }

    /// dump encrypted: XOR each byte with clientKey, emit only ciphertext
    function dumpEncrypted(uint256 id, DumpSecType dtype) external {
        bytes32 key = clientKey[msg.sender];
        if (key == bytes32(0)) revert DS__InvalidKey();
        bytes memory plain = records[id];
        bytes memory ct = new bytes(plain.length);
        for (uint i = 0; i < plain.length; i++) {
            ct[i] = plain[i] ^ key[i % 32];
        }
        emit EncryptedDump(msg.sender, id, dtype, DumpSecDefenseType.Encryption, ct);
    }
}
