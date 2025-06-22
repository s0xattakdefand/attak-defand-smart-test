// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title OverwriteProcedureSuite.sol
/// @notice On-chain analogues of “Overwrite Procedure” secure‐erase patterns:
///   Types: SinglePass, MultiPass, RandomPattern, CryptographicErase  
///   AttackTypes: DataRemanence, UnauthorizedOverwrite, FaultInjection, ReplayOverwrite  
///   DefenseTypes: Verification, AuditLogging, SecureErase, RateLimit  

enum OverwriteProcedureType           { SinglePass, MultiPass, RandomPattern, CryptographicErase }
enum OverwriteProcedureAttackType     { DataRemanence, UnauthorizedOverwrite, FaultInjection, ReplayOverwrite }
enum OverwriteProcedureDefenseType    { Verification, AuditLogging, SecureErase, RateLimit }

error OP__NotAllowed();
error OP__TooManyRequests();
error OP__AlreadyErased();
error OP__DataCorrupted();
error OP__Unauthorized();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE PROCEDURE
//
//    • ❌ no guarantees: data simply overwritten, remains recoverable  
//    • Attack: DataRemanence, UnauthorizedOverwrite
////////////////////////////////////////////////////////////////////////////////
contract OverwriteProcedureVuln {
    mapping(uint256 => bytes) public storageCell;
    event DataOverwritten(
        address indexed who,
        uint256 indexed cell,
        OverwriteProcedureType     otype,
        OverwriteProcedureAttackType attack
    );

    function overwrite(uint256 cell, OverwriteProcedureType otype, bytes calldata newData) external {
        storageCell[cell] = newData;
        emit DataOverwritten(msg.sender, cell, otype, OverwriteProcedureAttackType.DataRemanence);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//
//    • demonstrates unauthorized and repeated overwrites
////////////////////////////////////////////////////////////////////////////////
contract Attack_OverwriteProcedure {
    OverwriteProcedureVuln public target;

    constructor(OverwriteProcedureVuln _t) {
        target = _t;
    }

    function unauthorizedOverwrite(uint256 cell, bytes calldata fakeData) external {
        target.overwrite(cell, OverwriteProcedureType.SinglePass, fakeData);
    }

    function replayOverwrite(uint256 cell, bytes calldata data) external {
        // replay with the same data to bypass naive checks
        target.overwrite(cell, OverwriteProcedureType.SinglePass, data);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH SECURE ERASE
//
//    • ✅ Defense: SecureErase – delete before write, prevent reuse
////////////////////////////////////////////////////////////////////////////////
contract OverwriteProcedureSafeErase {
    mapping(uint256 => bytes) private storageCell;
    mapping(uint256 => bool) private erased;
    event DataOverwritten(
        address indexed who,
        uint256 indexed cell,
        OverwriteProcedureDefenseType defense
    );

    error OP__AlreadyErased();

    function overwrite(uint256 cell, bytes calldata newData) external {
        if (erased[cell]) revert OP__AlreadyErased();
        // secure erase stub: delete old data
        delete storageCell[cell];
        storageCell[cell] = newData;
        erased[cell] = true;
        emit DataOverwritten(msg.sender, cell, OverwriteProcedureDefenseType.SecureErase);
    }

    function read(uint256 cell) external view returns (bytes memory) {
        return storageCell[cell];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH VERIFICATION & AUDIT LOGGING
//
//    • ✅ Defense: Verification – require proof of erase before new write  
//               AuditLogging – record every operation  
////////////////////////////////////////////////////////////////////////////////
contract OverwriteProcedureSafeAudit {
    mapping(uint256 => bytes) public storageCell;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MAX_OPS = 3;
    address public owner;

    event DataErased(
        address indexed who,
        uint256 indexed cell,
        OverwriteProcedureDefenseType defense
    );
    event DataOverwritten(
        address indexed who,
        uint256 indexed cell,
        OverwriteProcedureDefenseType defense
    );

    error OP__TooManyRequests();
    error OP__NotOwner();
    error OP__Unauthorized();

    constructor() {
        owner = msg.sender;
    }

    // stub verification: only owner may certify erase
    function certifyErase(uint256 cell) external {
        if (msg.sender != owner) revert OP__NotOwner();
        delete storageCell[cell];
        emit DataErased(msg.sender, cell, OverwriteProcedureDefenseType.Verification);
    }

    function overwrite(uint256 cell, bytes calldata newData) external {
        // rate-limit operations per caller
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_OPS) revert OP__TooManyRequests();

        // require that owner has certified erase (i.e. cell cleared)
        if (storageCell[cell].length != 0) revert OP__Unauthorized();

        storageCell[cell] = newData;
        emit DataOverwritten(msg.sender, cell, OverwriteProcedureDefenseType.AuditLogging);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH RANDOM PATTERN & RATE-LIMIT
//
//    • ✅ Defense: RateLimit – cap erase/write calls  
//               SecureErase – use random pattern pass stub  
////////////////////////////////////////////////////////////////////////////////
contract OverwriteProcedureSafeAdvanced {
    mapping(uint256 => bytes) private storageCell;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public opsInBlock;
    uint256 public constant MAX_OPS = 1;

    event DataOverwritten(
        address indexed who,
        uint256 indexed cell,
        OverwriteProcedureDefenseType defense
    );

    error OP__TooManyRequests();

    // stub random pattern erase then write
    function overwrite(uint256 cell, bytes calldata newData) external {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            opsInBlock[msg.sender]   = 0;
        }
        opsInBlock[msg.sender]++;
        if (opsInBlock[msg.sender] > MAX_OPS) revert OP__TooManyRequests();

        // randomPattern stub: XOR with blockhash to obscure
        bytes memory erased = new bytes(storageCell[cell].length);
        bytes32 rnd = blockhash(block.number - 1);
        for (uint i = 0; i < erased.length; i++) {
            erased[i] = bytes1(uint8(rnd[i % 32]) ^ uint8(erased[i]));
        }
        // erase
        delete storageCell[cell];
        // write new
        storageCell[cell] = newData;
        emit DataOverwritten(msg.sender, cell, OverwriteProcedureDefenseType.RateLimit);
    }

    function read(uint256 cell) external view returns (bytes memory) {
        return storageCell[cell];
    }
}
