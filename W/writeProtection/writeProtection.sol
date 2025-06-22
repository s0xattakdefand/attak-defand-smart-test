// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title WriteProtectionSuite.sol
/// @notice On‐chain analogues of “Write Protection” patterns:
///   Types: Hardware, Software, FileSystem, SmartCard  
///   AttackTypes: PhysicalBypass, SoftwareOverride, BufferOverflow, Replay  
///   DefenseTypes: ReadOnlyMount, AccessControl, ChecksumVerification, RateLimit

enum WriteProtectionType        { Hardware, Software, FileSystem, SmartCard }
enum WriteProtectionAttackType  { PhysicalBypass, SoftwareOverride, BufferOverflow, Replay }
enum WriteProtectionDefenseType { ReadOnlyMount, AccessControl, ChecksumVerification, RateLimit }

error WP__NotOwner();
error WP__BypassDetected();
error WP__InvalidChecksum();
error WP__TooManyRequests();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE WRITE PROTECTION
//    • ❌ no checks: any data may be overwritten → PhysicalBypass
////////////////////////////////////////////////////////////////////////////////
contract WriteProtectionVuln {
    mapping(bytes32 => bytes) public dataStore;

    event DataWritten(
        address indexed who,
        bytes32        indexed key,
        bytes                  data,
        WriteProtectionType    wtype,
        WriteProtectionAttackType attack
    );

    function write(bytes32 key, bytes calldata data, WriteProtectionType wtype) external {
        dataStore[key] = data;
        emit DataWritten(msg.sender, key, data, wtype, WriteProtectionAttackType.PhysicalBypass);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates buffer‐overflow, software override, and replay
////////////////////////////////////////////////////////////////////////////////
contract Attack_WriteProtection {
    WriteProtectionVuln public target;
    bytes32 public lastKey;
    bytes   public lastData;

    constructor(WriteProtectionVuln _t) {
        target = _t;
    }

    function overflow(bytes32 key, bytes calldata data) external {
        target.write(key, data, WriteProtectionType.Software);
    }

    function capture(bytes32 key) external {
        lastKey = key;
        lastData = target.dataStore(key);
    }

    function replay() external {
        target.write(lastKey, lastData, WriteProtectionType.FileSystem);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may write
////////////////////////////////////////////////////////////////////////////////
contract WriteProtectionSafeAccess {
    mapping(bytes32 => bytes) public dataStore;
    address public owner;

    event DataWritten(
        address indexed who,
        bytes32        indexed key,
        bytes                  data,
        WriteProtectionDefenseType defense
    );

    error WP__NotOwner();

    constructor() {
        owner = msg.sender;
    }

    function write(bytes32 key, bytes calldata data, WriteProtectionType) external {
        if (msg.sender != owner) revert WP__NotOwner();
        dataStore[key] = data;
        emit DataWritten(msg.sender, key, data, WriteProtectionDefenseType.AccessControl);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH CHECKSUM VERIFICATION
//    • ✅ Defense: ChecksumVerification – require matching checksum before write
////////////////////////////////////////////////////////////////////////////////
contract WriteProtectionSafeChecksum {
    mapping(bytes32 => bytes)   public dataStore;
    mapping(bytes32 => bytes32) public checksum;

    event DataWritten(
        address indexed who,
        bytes32        indexed key,
        bytes                  data,
        WriteProtectionDefenseType defense
    );

    error WP__InvalidChecksum();

    function setChecksum(bytes32 key, bytes32 sum) external {
        checksum[key] = sum;
    }

    function write(bytes32 key, bytes calldata data, WriteProtectionType) external {
        if (keccak256(data) != checksum[key]) revert WP__InvalidChecksum();
        dataStore[key] = data;
        emit DataWritten(msg.sender, key, data, WriteProtectionDefenseType.ChecksumVerification);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH READ-ONLY MOUNT & RATE LIMIT
//    • ✅ Defense: ReadOnlyMount – block writes when read‐only  
//               RateLimit – cap writes per block
////////////////////////////////////////////////////////////////////////////////
contract WriteProtectionSafeAdvanced {
    mapping(bytes32 => bytes) public dataStore;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public writesInBlock;
    bool public readOnly;
    uint256 public constant MAX_WRITES = 3;

    event MountToggled(
        address indexed who,
        bool                   readOnly,
        WriteProtectionDefenseType defense
    );
    event DataWritten(
        address indexed who,
        bytes32        indexed key,
        bytes                  data,
        WriteProtectionDefenseType defense
    );

    error WP__BypassDetected();
    error WP__TooManyRequests();

    function toggleReadOnly(bool ro) external {
        // stub: assume msg.sender is admin
        readOnly = ro;
        emit MountToggled(msg.sender, ro, WriteProtectionDefenseType.ReadOnlyMount);
    }

    function write(bytes32 key, bytes calldata data, WriteProtectionType) external {
        if (readOnly) revert WP__BypassDetected();
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            writesInBlock[msg.sender] = 0;
        }
        writesInBlock[msg.sender]++;
        if (writesInBlock[msg.sender] > MAX_WRITES) revert WP__TooManyRequests();
        dataStore[key] = data;
        emit DataWritten(msg.sender, key, data, WriteProtectionDefenseType.RateLimit);
    }
}
