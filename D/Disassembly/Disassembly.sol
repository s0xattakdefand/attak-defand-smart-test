// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DisassemblySuite.sol
/// @notice On‑chain analogues of “Disassembly” analysis patterns:
///   Types: Static, Dynamic, Interactive, BinaryDiff  
///   AttackTypes: CodeExtraction, Debugging, Tampering, ReplayAnalysis  
///   DefenseTypes: Obfuscation, AntiDebug, IntegrityCheck, CodeEncryption  

enum DisassemblyType         { Static, Dynamic, Interactive, BinaryDiff }
enum DisassemblyAttackType   { CodeExtraction, Debugging, Tampering, ReplayAnalysis }
enum DisassemblyDefenseType  { Obfuscation, AntiDebug, IntegrityCheck, CodeEncryption }

error DIS__NotOwner();
error DIS__BadKey();
error DIS__Tampered();
error DIS__TooMany();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE DISASSEMBLER
//
//    • ❌ anyone may extract on‑chain “bytecode” with no control  
//    • AttackType: CodeExtraction
////////////////////////////////////////////////////////////////////////////////
contract DisassemblyVuln {
    event Disassembled(
        address indexed who,
        DisassemblyType dtype,
        bytes           code,
        DisassemblyAttackType attack
    );

    /// anyone can call and receive runtime bytecode
    function disassemble(address target, DisassemblyType dtype) external {
        bytes memory c = target.code;
        emit Disassembled(msg.sender, dtype, c, DisassemblyAttackType.CodeExtraction);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//
//    • demonstrates automated code dump and code tampering
////////////////////////////////////////////////////////////////////////////////
contract Attack_Disassembly {
    DisassemblyVuln public target;
    constructor(DisassemblyVuln _t) { target = _t; }

    /// automate dumping code
    function dump(address t) external {
        target.disassemble(t, DisassemblyType.Static);
    }

    /// simulate tampering by writing to a dummy storage slot
    function tamper() external {
        // no real effect on external code, just logging
        emit TamperLog(msg.sender, DisassemblyAttackType.Tampering);
    }
    event TamperLog(address indexed who, DisassemblyAttackType attack);
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE DISASSEMBLER (OWNER‑ONLY + RATE‑LIMIT + INTEGRITY CHECK)
//
//    • Defense: AccessControl (only owner)  
//               RateLimit (cap per block)  
//               IntegrityCheck (hash match)  
////////////////////////////////////////////////////////////////////////////////
contract DisassemblySafe {
    address public owner;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public countInBlock;
    mapping(address => bytes32)  public knownHash;
    uint256 public constant MAX_PER_BLOCK = 3;

    event Disassembled(
        address indexed who,
        DisassemblyType dtype,
        bytes           code,
        DisassemblyDefenseType defense
    );

    error DIS__TooMany();
    error DIS__BadHash();

    constructor() {
        owner = msg.sender;
    }

    /// owner registers expected code hash for a target
    function registerHash(address target, bytes32 hash) external {
        require(msg.sender == owner, "only owner");
        knownHash[target] = hash;
    }

    /// protected disassemble
    function disassemble(address target, DisassemblyType dtype) external {
        if (msg.sender != owner) revert DIS__NotOwner();
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender]++;
        if (countInBlock[msg.sender] > MAX_PER_BLOCK) revert DIS__TooMany();

        bytes memory c = target.code;
        // integrity check: require code hash matches registered
        if (keccak256(c) != knownHash[target]) revert DIS__BadHash();
        emit Disassembled(msg.sender, dtype, c, DisassemblyDefenseType.IntegrityCheck);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE ADVANCED DISASSEMBLER (CODE ENCRYPTION + ANTI‑DEBUG)
//
//    • Defense: CodeEncryption (store encrypted blob)  
//               AntiDebug (detect high call frequency)
////////////////////////////////////////////////////////////////////////////////
contract DisassemblySafeAdvanced {
    address public owner;
    mapping(address => bytes)    private encryptedCode;
    mapping(address => uint256)  public lastCallTime;
    uint256 public constant MIN_INTERVAL = 10 seconds;

    event Disassembled(
        address indexed who,
        DisassemblyType dtype,
        bytes           code,
        DisassemblyDefenseType defense
    );

    constructor() {
        owner = msg.sender;
    }

    /// owner stores encrypted code blob for a target
    function storeEncrypted(address target, bytes calldata blob) external {
        require(msg.sender == owner, "only owner");
        encryptedCode[target] = blob;
    }

    /// decrypt and return code, with anti‑debug timing check
    function disassemble(
        address target,
        DisassemblyType dtype,
        bytes calldata key
    ) external {
        // anti‑debug: enforce minimum time between calls
        uint256 since = block.timestamp - lastCallTime[msg.sender];
        require(since >= MIN_INTERVAL, "anti-debug: too fast");
        lastCallTime[msg.sender] = block.timestamp;

        // stub decryption: XOR with keccak256(key)
        bytes memory blob = encryptedCode[target];
        bytes32 mask = keccak256(key);
        bytes memory c = new bytes(blob.length);
        for (uint i = 0; i < blob.length; i++) {
            c[i] = blob[i] ^ mask[i % 32];
        }

        emit Disassembled(msg.sender, dtype, c, DisassemblyDefenseType.CodeEncryption);
    }
}
