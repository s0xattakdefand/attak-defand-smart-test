// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title OTPMemorySuite.sol
/// @notice On-chain analogues of “One-Time Programmable Memory” patterns:
///   Types: FuseBased, MaskProgrammable, AntiTamper, EPROMOneTime  
///   AttackTypes: Overwrite, GlitchWrite, SideChannelRead, FaultInjection  
///   DefenseTypes: WriteLock, AccessControl, ECCProtection, Redundancy  

enum OTPMemoryType             { FuseBased, MaskProgrammable, AntiTamper, EPROMOneTime }
enum OTPMemoryAttackType       { Overwrite, GlitchWrite, SideChannelRead, FaultInjection }
enum OTPMemoryDefenseType      { WriteLock, AccessControl, ECCProtection, Redundancy }

error OTPM__AlreadyProgrammed();
error OTPM__Unauthorized();
error OTPM__DataCorrupted();
error OTPM__TooFrequent();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE OTP MEMORY
//
//    • no write protection, any caller may program or overwrite → Overwrite
////////////////////////////////////////////////////////////////////////////////
contract OTPMemoryVuln {
    mapping(uint256 => bytes) public cells;
    event MemoryWritten(
        address indexed by,
        uint256          addr,
        bytes            data,
        OTPMemoryAttackType attack
    );
    event MemoryRead(
        address indexed by,
        uint256          addr,
        bytes            data,
        OTPMemoryAttackType attack
    );

    function write(uint256 addr, bytes calldata data) external {
        cells[addr] = data;
        emit MemoryWritten(msg.sender, addr, data, OTPMemoryAttackType.Overwrite);
    }

    function read(uint256 addr) external view returns (bytes memory) {
        bytes memory d = cells[addr];
        emit MemoryRead(msg.sender, addr, d, OTPMemoryAttackType.SideChannelRead);
        return d;
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//
//    • simulates glitch writes and repeated overwrites
////////////////////////////////////////////////////////////////////////////////
contract Attack_OTPMemory {
    OTPMemoryVuln public target;
    constructor(OTPMemoryVuln _t) { target = _t; }

    function floodWrite(uint256 addr, bytes calldata data, uint count) external {
        for (uint i = 0; i < count; i++) {
            target.write(addr, data);
        }
    }

    function glitch(uint256 addr, bytes calldata badData) external {
        // simulate fault injection
        target.write(addr, badData);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH WRITE-LOCK
//
//    • Defense: WriteLock – each address programmable only once
////////////////////////////////////////////////////////////////////////////////
contract OTPMemorySafeWriteLock {
    mapping(uint256 => bytes) private cells;
    mapping(uint256 => bool)  private locked;
    event MemoryWritten(
        uint256          addr,
        OTPMemoryDefenseType defense,
        bytes            data
    );

    function write(uint256 addr, bytes calldata data) external {
        if (locked[addr]) revert OTPM__AlreadyProgrammed();
        cells[addr] = data;
        locked[addr] = true;
        emit MemoryWritten(addr, OTPMemoryDefenseType.WriteLock, data);
    }

    function read(uint256 addr) external view returns (bytes memory) {
        return cells[addr];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH ACCESS CONTROL & ECC PROTECTION
//
//    • Defense: AccessControl – only owner may program  
//               ECCProtection – verify simple parity
////////////////////////////////////////////////////////////////////////////////
contract OTPMemorySafeECC {
    mapping(uint256 => bytes) private cells;
    mapping(uint256 => uint8)  private parity;
    address public owner;

    event MemoryWritten(
        uint256          addr,
        OTPMemoryDefenseType defense,
        bytes            data
    );
    event MemoryRead(
        uint256          addr,
        bytes            data,
        OTPMemoryDefenseType defense
    );

    error OTPM__NotOwner();
    error OTPM__DataCorrupted();

    constructor() {
        owner = msg.sender;
    }

    function write(uint256 addr, bytes calldata data, uint8 expectedParity) external {
        if (msg.sender != owner) revert OTPM__Unauthorized();
        // compute parity = XOR of all bytes
        uint8 p = 0;
        for (uint i = 0; i < data.length; i++) {
            p ^= uint8(data[i]);
        }
        if (p != expectedParity) revert OTPM__DataCorrupted();
        cells[addr] = data;
        parity[addr] = p;
        emit MemoryWritten(addr, OTPMemoryDefenseType.ECCProtection, data);
    }

    function read(uint256 addr) external returns (bytes memory) {
        bytes memory d = cells[addr];
        uint8 p = 0;
        for (uint i = 0; i < d.length; i++) {
            p ^= uint8(d[i]);
        }
        if (p != parity[addr]) revert OTPM__DataCorrupted();
        emit MemoryRead(addr, d, OTPMemoryDefenseType.ECCProtection);
        return d;
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH REDUNDANCY & RATE-LIMIT
//
//    • Defense: Redundancy – mirror data across three cells, majority vote  
//               RateLimit – cap writes per block per addr
////////////////////////////////////////////////////////////////////////////////
contract OTPMemorySafeAdvanced {
    struct Triple { bytes a; bytes b; bytes c; }
    mapping(uint256 => Triple) private cells;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public writesInBlock;
    uint256 public constant MAX_WRITES = 1;

    event MemoryWritten(
        uint256          addr,
        OTPMemoryDefenseType defense,
        bytes            data
    );

    error OTPM__TooFrequent();

    function write(uint256 addr, bytes calldata data) external {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            writesInBlock[msg.sender] = 0;
        }
        writesInBlock[msg.sender]++;
        if (writesInBlock[msg.sender] > MAX_WRITES) revert OTPM__TooFrequent();

        Triple storage t = cells[addr];
        t.a = data;
        t.b = data;
        t.c = data;
        emit MemoryWritten(addr, OTPMemoryDefenseType.Redundancy, data);
    }

    function read(uint256 addr) external view returns (bytes memory) {
        Triple storage t = cells[addr];
        // simple majority vote stub: return a if equal to b or c, else b
        if (keccak256(t.a) == keccak256(t.b) || keccak256(t.a) == keccak256(t.c)) {
            return t.a;
        } else if (keccak256(t.b) == keccak256(t.c)) {
            return t.b;
        } else {
            return t.a; // fallback
        }
    }
}
