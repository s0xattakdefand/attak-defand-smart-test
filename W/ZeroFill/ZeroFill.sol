// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title ZeroFillSuite.sol
/// @notice On-chain analogues of “Zero Fill” secure‐erase patterns:
///   Types: Memory, Storage, TempBuffer, File  
///   AttackTypes: DataRemanence, FaultInjection, Replay  
///   DefenseTypes: SecureErase, Verification, MultiPass, RateLimit  

enum ZeroFillType          { Memory, Storage, TempBuffer, File }
enum ZeroFillAttackType    { DataRemanence, FaultInjection, Replay }
enum ZeroFillDefenseType   { SecureErase, Verification, MultiPass, RateLimit }

error ZF__NotAllowed();
error ZF__TooFrequent();
error ZF__NotZeroed();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE ZERO‐FILL
//    • ❌ release without wiping → DataRemanence
////////////////////////////////////////////////////////////////////////////////
contract ZeroFillVuln {
    mapping(uint256 => bytes) public dataStore;
    event DataWritten(uint256 indexed id, ZeroFillType t, bytes data);
    event DataReleased(uint256 indexed id, ZeroFillType t, ZeroFillAttackType attack);

    function writeData(uint256 id, ZeroFillType t, bytes calldata data) external {
        dataStore[id] = data;
        emit DataWritten(id, t, data);
    }

    function release(uint256 id, ZeroFillType t) external {
        // ❌ simply delete reference, underlying remnants remain
        delete dataStore[id];
        emit DataReleased(id, t, ZeroFillAttackType.DataRemanence);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • capture stale data or replay after release
////////////////////////////////////////////////////////////////////////////////
contract Attack_ZeroFill {
    ZeroFillVuln public target;
    bytes public captured;

    constructor(ZeroFillVuln _t) {
        target = _t;
    }

    function capture(uint256 id) external {
        // read before release
        captured = target.dataStore(id);
    }

    function replay(uint256 id, ZeroFillType t) external {
        // attacker re-inserts stale or fake data
        target.writeData(id, t, captured);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE ZERO‐FILL WITH SECURE ERASE
//    • ✅ Defense: SecureErase – overwrite with zeros
////////////////////////////////////////////////////////////////////////////////
contract ZeroFillSafeSecure {
    mapping(uint256 => bytes) private dataStore;
    event DataReleased(uint256 indexed id, ZeroFillType t, ZeroFillDefenseType defense);

    function writeData(uint256 id, ZeroFillType t, bytes calldata data) external {
        dataStore[id] = data;
    }

    function release(uint256 id, ZeroFillType t) external {
        bytes storage d = dataStore[id];
        // overwrite each byte with zero
        for (uint i = 0; i < d.length; i++) {
            d[i] = 0;
        }
        delete dataStore[id];
        emit DataReleased(id, t, ZeroFillDefenseType.SecureErase);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE ZERO‐FILL WITH VERIFICATION
//    • ✅ Defense: Verification – ensure buffer is zeroed
////////////////////////////////////////////////////////////////////////////////
contract ZeroFillSafeVerify {
    mapping(uint256 => bytes) private dataStore;
    event DataReleased(uint256 indexed id, ZeroFillType t, ZeroFillDefenseType defense);

    error ZF__NotZeroed();

    function writeData(uint256 id, ZeroFillType t, bytes calldata data) external {
        dataStore[id] = data;
    }

    function release(uint256 id, ZeroFillType t) external {
        bytes storage d = dataStore[id];
        // overwrite
        for (uint i = 0; i < d.length; i++) {
            d[i] = 0;
        }
        // verify all zeros
        for (uint i = 0; i < d.length; i++) {
            if (d[i] != 0) revert ZF__NotZeroed();
        }
        delete dataStore[id];
        emit DataReleased(id, t, ZeroFillDefenseType.Verification);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED ZERO‐FILL WITH MULTI‐PASS & RATE‐LIMIT
//    • ✅ Defense: MultiPass – multiple zero‐write passes  
//               RateLimit – cap releases per block
////////////////////////////////////////////////////////////////////////////////
contract ZeroFillSafeAdvanced {
    mapping(uint256 => bytes) private dataStore;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public releasesInBlock;
    uint256 public constant MAX_RELEASES = 2;

    event DataReleased(uint256 indexed id, ZeroFillType t, ZeroFillDefenseType defense);
    error ZF__TooFrequent();

    function writeData(uint256 id, ZeroFillType t, bytes calldata data) external {
        dataStore[id] = data;
    }

    function release(uint256 id, ZeroFillType t) external {
        // rate-limit per caller
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            releasesInBlock[msg.sender] = 0;
        }
        releasesInBlock[msg.sender]++;
        if (releasesInBlock[msg.sender] > MAX_RELEASES) revert ZF__TooFrequent();

        bytes storage d = dataStore[id];
        // multi-pass zero fill: two passes
        for (uint pass = 0; pass < 2; pass++) {
            for (uint i = 0; i < d.length; i++) {
                d[i] = 0;
            }
        }
        delete dataStore[id];
        emit DataReleased(id, t, ZeroFillDefenseType.MultiPass);
    }
}
