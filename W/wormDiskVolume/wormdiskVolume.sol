// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title WormDiskVolumeSuite.sol
/// @notice On‐chain analogues of “WORM Disk Volume” (Write Once Read Many) patterns:
///   Types: OpticalDisk, MagneticTape, FlashWORM, VirtualWORM  
///   AttackTypes: Overwrite, Tampering, Spoofing, Deletion  
///   DefenseTypes: ImmutableStorage, AccessControl, HashVerification, AuditLogging

enum WormDiskVolumeType         { OpticalDisk, MagneticTape, FlashWORM, VirtualWORM }
enum WormDiskVolumeAttackType   { Overwrite, Tampering, Spoofing, Deletion }
enum WormDiskVolumeDefenseType  { ImmutableStorage, AccessControl, HashVerification, AuditLogging }

error WDV__AlreadyWritten();
error WDV__NotAuthorized();
error WDV__HashMismatch();
error WDV__TooManyWrites();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE VOLUME
//    • ❌ no protection: data may be overwritten or deleted → Overwrite, Deletion
////////////////////////////////////////////////////////////////////////////////
contract WormDiskVolumeVuln {
    mapping(bytes32 => bytes) public volume;
    event DataWritten(
        address indexed who,
        bytes32           volId,
        WormDiskVolumeType vtype,
        bytes             data,
        WormDiskVolumeAttackType attack
    );

    function writeData(bytes32 volId, WormDiskVolumeType vtype, bytes calldata data) external {
        volume[volId] = data;
        emit DataWritten(msg.sender, volId, vtype, data, WormDiskVolumeAttackType.Overwrite);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates tampering, replay, spoofing
////////////////////////////////////////////////////////////////////////////////
contract Attack_WormDiskVolume {
    WormDiskVolumeVuln public target;
    bytes32 public lastVol;
    bytes   public lastData;

    constructor(WormDiskVolumeVuln _t) {
        target = _t;
    }

    function tamper(bytes32 volId, bytes calldata fake) external {
        target.writeData(volId, WormDiskVolumeType.OpticalDisk, fake);
    }

    function capture(bytes32 volId) external {
        lastVol = volId;
        lastData = target.volume(volId);
    }

    function replay() external {
        target.writeData(lastVol, WormDiskVolumeType.OpticalDisk, lastData);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH IMMUTABLE STORAGE
//    • ✅ Defense: ImmutableStorage – first write only, thereafter locked
////////////////////////////////////////////////////////////////////////////////
contract WormDiskVolumeSafeImmutable {
    mapping(bytes32 => bytes) public volume;
    mapping(bytes32 => bool)  public written;
    event DataWritten(
        address indexed who,
        bytes32           volId,
        bytes             data,
        WormDiskVolumeDefenseType defense
    );

    function writeData(bytes32 volId, bytes calldata data) external {
        if (written[volId]) revert WDV__AlreadyWritten();
        volume[volId] = data;
        written[volId] = true;
        emit DataWritten(msg.sender, volId, data, WormDiskVolumeDefenseType.ImmutableStorage);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may write
////////////////////////////////////////////////////////////////////////////////
contract WormDiskVolumeSafeAccess {
    mapping(bytes32 => bytes) public volume;
    address public owner;
    event DataWritten(
        address indexed who,
        bytes32           volId,
        bytes             data,
        WormDiskVolumeDefenseType defense
    );

    error WDV__NotAuthorized();

    constructor() {
        owner = msg.sender;
    }

    function writeData(bytes32 volId, bytes calldata data) external {
        if (msg.sender != owner) revert WDV__NotAuthorized();
        volume[volId] = data;
        emit DataWritten(msg.sender, volId, data, WormDiskVolumeDefenseType.AccessControl);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH HASH VERIFICATION & RATE LIMIT
//    • ✅ Defense: HashVerification – require data hash match expected  
//               AuditLogging – record every write, cap writes per block
////////////////////////////////////////////////////////////////////////////////
contract WormDiskVolumeSafeAdvanced {
    mapping(bytes32 => bytes)   public volume;
    mapping(bytes32 => bytes32) public expectedHash; // volId → keccak256(data)
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public writesInBlock;
    uint256 public constant MAX_WRITES = 3;

    event AuditLog(
        address indexed who,
        bytes32           volId,
        WormDiskVolumeDefenseType defense
    );
    event DataWritten(
        address indexed who,
        bytes32           volId,
        bytes             data,
        WormDiskVolumeDefenseType defense
    );

    error WDV__HashMismatch();
    error WDV__TooManyWrites();

    /// admin sets expected data hash
    function setExpectedHash(bytes32 volId, bytes32 hash_) external {
        expectedHash[volId] = hash_;
    }

    function writeData(bytes32 volId, bytes calldata data) external {
        // rate-limit per writer
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            writesInBlock[msg.sender] = 0;
        }
        writesInBlock[msg.sender]++;
        if (writesInBlock[msg.sender] > MAX_WRITES) revert WDV__TooManyWrites();

        // hash verification
        if (keccak256(data) != expectedHash[volId]) revert WDV__HashMismatch();

        // audit and write
        emit AuditLog(msg.sender, volId, WormDiskVolumeDefenseType.HashVerification);
        volume[volId] = data;
        emit DataWritten(msg.sender, volId, data, WormDiskVolumeDefenseType.AuditLogging);
    }
}
