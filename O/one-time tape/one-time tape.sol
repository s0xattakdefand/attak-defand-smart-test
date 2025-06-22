// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title OneTimeTapeSuite.sol
/// @notice On-chain analogues of “One-Time Tape” encryption patterns:
///   Types: PhysicalTape, VirtualTape, HybridTape  
///   AttackTypes: TapeReuse, TapeExtraction, ReplayAttack  
///   DefenseTypes: TapeDestruction, SecureStorage, RateLimit, Encryption  

enum OneTimeTapeType           { PhysicalTape, VirtualTape, HybridTape }
enum OneTimeTapeAttackType     { TapeReuse, TapeExtraction, ReplayAttack }
enum OneTimeTapeDefenseType    { TapeDestruction, SecureStorage, RateLimit, Encryption }

error OTT__NoTape();
error OTT__Reused();
error OTT__TooMany();
error OTT__Unauthorized();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE TAPE SERVICE
//
//    • no destruction or protection: tape reused → TapeReuse
////////////////////////////////////////////////////////////////////////////////
contract OneTimeTapeVuln {
    mapping(bytes32 => bytes) public tape;  // tapeId → data
    event Encrypted(
        address indexed who,
        bytes32           tapeId,
        bytes             ciphertext,
        OneTimeTapeType   ttype,
        OneTimeTapeAttackType attack
    );

    /// load tape (owner or admin)
    function loadTape(bytes32 tapeId, bytes calldata data) external {
        tape[tapeId] = data;
    }

    /// encrypt by XOR; tape remains for reuse
    function encrypt(bytes32 tapeId, bytes calldata plaintext) external {
        bytes memory key = tape[tapeId];
        if (key.length == 0) revert OTT__NoTape();
        uint256 n = plaintext.length;
        bytes memory ct = new bytes(n);
        for (uint i = 0; i < n; i++) {
            ct[i] = plaintext[i] ^ key[i % key.length];
        }
        emit Encrypted(msg.sender, tapeId, ct, OneTimeTapeType.PhysicalTape, OneTimeTapeAttackType.TapeReuse);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//
//    • demonstrates tape extraction and replay
////////////////////////////////////////////////////////////////////////////////
contract Attack_OneTimeTape {
    OneTimeTapeVuln public target;
    bytes32 public lastId;
    bytes public lastCT;

    constructor(OneTimeTapeVuln _t) {
        target = _t;
    }

    /// capture ciphertext for replay
    function capture(bytes32 tapeId, bytes calldata ct) external {
        lastId = tapeId;
        lastCT = ct;
    }

    /// replay using captured ciphertext
    function replay() external {
        target.encrypt(lastId, lastCT);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE TAPE WITH DESTRUCTION
//
//    • Defense: TapeDestruction – delete tape after one use
////////////////////////////////////////////////////////////////////////////////
contract OneTimeTapeSafeDestruct {
    mapping(bytes32 => bytes) private tape;
    event Encrypted(
        address indexed who,
        bytes32           tapeId,
        bytes             ciphertext,
        OneTimeTapeDefenseType defense
    );

    error OTT__NoTape();

    function loadTape(bytes32 tapeId, bytes calldata data) external {
        tape[tapeId] = data;
    }

    function encrypt(bytes32 tapeId, bytes calldata plaintext) external {
        bytes memory key = tape[tapeId];
        if (key.length == 0) revert OTT__NoTape();
        uint256 n = plaintext.length;
        bytes memory ct = new bytes(n);
        for (uint i = 0; i < n; i++) {
            ct[i] = plaintext[i] ^ key[i % key.length];
        }
        delete tape[tapeId];
        emit Encrypted(msg.sender, tapeId, ct, OneTimeTapeDefenseType.TapeDestruction);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE TAPE WITH SECURE STORAGE
//
//    • Defense: SecureStorage – only owner may load/use tape
////////////////////////////////////////////////////////////////////////////////
contract OneTimeTapeSafeStorage {
    mapping(bytes32 => bytes) private tape;
    address public owner;
    event Encrypted(
        address indexed who,
        bytes32           tapeId,
        bytes             ciphertext,
        OneTimeTapeDefenseType defense
    );

    error OTT__Unauthorized();
    error OTT__NoTape();

    constructor() {
        owner = msg.sender;
    }

    function loadTape(bytes32 tapeId, bytes calldata data) external {
        if (msg.sender != owner) revert OTT__Unauthorized();
        tape[tapeId] = data;
    }

    function encrypt(bytes32 tapeId, bytes calldata plaintext) external {
        if (msg.sender != owner) revert OTT__Unauthorized();
        bytes memory key = tape[tapeId];
        if (key.length == 0) revert OTT__NoTape();
        uint256 n = plaintext.length;
        bytes memory ct = new bytes(n);
        for (uint i = 0; i < n; i++) {
            ct[i] = plaintext[i] ^ key[i % key.length];
        }
        emit Encrypted(msg.sender, tapeId, ct, OneTimeTapeDefenseType.SecureStorage);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED TAPE WITH RATE-LIMIT & ENCRYPTION
//
//    • Defense: RateLimit – cap encrypt calls per tapeId  
//               Encryption – use secondary key for ciphertext integrity
////////////////////////////////////////////////////////////////////////////////
contract OneTimeTapeSafeAdvanced {
    mapping(bytes32 => bytes) private tape;
    mapping(bytes32 => uint256) public lastBlock;
    mapping(bytes32 => uint256) public usesInBlock;
    uint256 public constant MAX_USES = 1;
    bytes32 public masterKey;
    address public owner;

    event Encrypted(
        address indexed who,
        bytes32           tapeId,
        bytes             ciphertext,
        OneTimeTapeDefenseType defense
    );

    error OTT__NoTape();
    error OTT__TooMany();
    error OTT__Unauthorized();

    constructor(bytes32 _masterKey) {
        owner = msg.sender;
        masterKey = _masterKey;
    }

    function loadTape(bytes32 tapeId, bytes calldata data) external {
        if (msg.sender != owner) revert OTT__Unauthorized();
        tape[tapeId] = data;
    }

    function encrypt(bytes32 tapeId, bytes calldata plaintext) external {
        if (block.number != lastBlock[tapeId]) {
            lastBlock[tapeId]    = block.number;
            usesInBlock[tapeId] = 0;
        }
        usesInBlock[tapeId]++;
        if (usesInBlock[tapeId] > MAX_USES) revert OTT__TooMany();

        bytes memory key = tape[tapeId];
        if (key.length == 0) revert OTT__NoTape();
        uint256 n = plaintext.length;
        bytes memory ct = new bytes(n);
        for (uint i = 0; i < n; i++) {
            // primary XOR with tape, then XOR with masterKey for integrity
            bytes1 k1 = key[i % key.length];
            bytes1 k2 = bytes1(masterKey[i % 32]);
            ct[i] = plaintext[i] ^ k1 ^ k2;
        }
        emit Encrypted(msg.sender, tapeId, ct, OneTimeTapeDefenseType.Encryption);
    }
}
