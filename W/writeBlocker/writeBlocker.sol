// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title WriteBlockerSuite.sol
/// @notice On‐chain analogues of “Write Blocker” patterns:
///   Types: USBHardware, PCIeHardware, SoftwareDriver, NetworkProxy  
///   AttackTypes: PhysicalBypass, SoftwareOverride, Replay, FirmwareTampering  
///   DefenseTypes: AccessControl, ImmutableMount, ProtocolInspection, RateLimit

enum WriteBlockerType           { USBHardware, PCIeHardware, SoftwareDriver, NetworkProxy }
enum WriteBlockerAttackType     { PhysicalBypass, SoftwareOverride, Replay, FirmwareTampering }
enum WriteBlockerDefenseType    { AccessControl, ImmutableMount, ProtocolInspection, RateLimit }

error WBLock__NotAuthorized();
error WBLock__BypassDetected();
error WBLock__TooManyRequests();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE WRITE BLOCKER
//    • ❌ no blocking: any write allowed → PhysicalBypass
////////////////////////////////////////////////////////////////////////////////
contract WriteBlockerVuln {
    mapping(bytes32 => bytes) public dataStore;

    event WriteAttempt(
        address indexed who,
        bytes32           key,
        WriteBlockerType  wtype,
        WriteBlockerAttackType attack
    );

    function write(
        bytes32 key,
        bytes calldata data,
        WriteBlockerType wtype
    ) external {
        dataStore[key] = data;
        emit WriteAttempt(msg.sender, key, wtype, WriteBlockerAttackType.PhysicalBypass);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates bypass, override, replay, firmware tampering
////////////////////////////////////////////////////////////////////////////////
contract Attack_WriteBlocker {
    WriteBlockerVuln public target;
    bytes32 public lastKey;
    bytes   public lastData;
    WriteBlockerType public lastType;

    constructor(WriteBlockerVuln _t) {
        target = _t;
    }

    function bypassPhysical(bytes32 key, bytes calldata data) external {
        target.write(key, data, WriteBlockerType.USBHardware);
        lastKey = key; lastData = data; lastType = WriteBlockerType.USBHardware;
    }

    function overrideSoftware(bytes32 key, bytes calldata data) external {
        target.write(key, data, WriteBlockerType.SoftwareDriver);
    }

    function replay() external {
        target.write(lastKey, lastData, lastType);
    }

    function tamperFirmware(bytes32 key, bytes calldata data) external {
        target.write(key, data, WriteBlockerType.PCIeHardware);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may write
////////////////////////////////////////////////////////////////////////////////
contract WriteBlockerSafeAccess {
    mapping(bytes32 => bytes) public dataStore;
    address public owner;

    event WriteBlocked(
        address indexed who,
        bytes32           key,
        WriteBlockerDefenseType defense
    );
    event WriteAllowed(
        address indexed who,
        bytes32           key,
        WriteBlockerDefenseType defense
    );

    constructor() {
        owner = msg.sender;
    }

    function write(
        bytes32 key,
        bytes calldata data,
        WriteBlockerType
    ) external {
        if (msg.sender != owner) {
            emit WriteBlocked(msg.sender, key, WriteBlockerDefenseType.AccessControl);
            revert WBLock__NotAuthorized();
        }
        dataStore[key] = data;
        emit WriteAllowed(msg.sender, key, WriteBlockerDefenseType.AccessControl);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH IMMUTABLE MOUNT
//    • ✅ Defense: ImmutableMount – block writes when mounted read‐only
////////////////////////////////////////////////////////////////////////////////
contract WriteBlockerSafeImmutable {
    mapping(bytes32 => bytes) public dataStore;
    bool public readOnly;

    event MountToggled(
        address indexed who,
        bool              readOnly,
        WriteBlockerDefenseType defense
    );
    event WriteAllowed(
        address indexed who,
        bytes32           key,
        WriteBlockerDefenseType defense
    );

    error WBLock__BypassDetected();

    function toggleReadOnly(bool ro) external {
        // stub: assume admin
        readOnly = ro;
        emit MountToggled(msg.sender, ro, WriteBlockerDefenseType.ImmutableMount);
    }

    function write(
        bytes32 key,
        bytes calldata data,
        WriteBlockerType
    ) external {
        if (readOnly) {
            revert WBLock__BypassDetected();
        }
        dataStore[key] = data;
        emit WriteAllowed(msg.sender, key, WriteBlockerDefenseType.ImmutableMount);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH PROTOCOL INSPECTION & RATE LIMIT
//    • ✅ Defense: ProtocolInspection – require `ok` flag  
//               RateLimit – cap writes per block per caller
////////////////////////////////////////////////////////////////////////////////
contract WriteBlockerSafeAdvanced {
    mapping(bytes32 => bytes) public dataStore;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public writesInBlock;
    uint256 public constant MAX_WRITES = 3;

    event WriteAllowed(
        address indexed who,
        bytes32           key,
        WriteBlockerDefenseType defense
    );
    error WBLock__BypassDetected();
    error WBLock__TooManyRequests();

    function write(
        bytes32 key,
        bytes calldata data,
        WriteBlockerType,
        bool protocolOk
    ) external {
        if (!protocolOk) revert WBLock__BypassDetected();

        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            writesInBlock[msg.sender] = 0;
        }
        writesInBlock[msg.sender]++;
        if (writesInBlock[msg.sender] > MAX_WRITES) revert WBLock__TooManyRequests();

        dataStore[key] = data;
        emit WriteAllowed(msg.sender, key, WriteBlockerDefenseType.RateLimit);
    }
}
