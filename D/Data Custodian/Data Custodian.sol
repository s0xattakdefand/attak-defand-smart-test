// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DataCustodianSuite.sol
/// @notice On‑chain analogues of “Data Custodian” patterns:
///   Types: Primary, Secondary, Backup, Archive  
///   AttackTypes: UnauthorizedAccess, Tampering, Deletion, Exfiltration  
///   DefenseTypes: AccessControl, ImmutableRecord, RateLimit, Encryption  

enum DataCustodianType        { Primary, Secondary, Backup, Archive }
enum DataCustodianAttackType  { UnauthorizedAccess, Tampering, Deletion, Exfiltration }
enum DataCustodianDefenseType { AccessControl, ImmutableRecord, RateLimit, Encryption }

error DC__NotOwner();
error DC__AlreadySet();
error DC__TooMany();
error DC__NoData();
error DC__NotEncrypted();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE CUSTODIAN
///    • no access control, mutable, no limits
///    • Attack: anyone may overwrite, delete or read data
///─────────────────────────────────────────────────────────────────────────────
contract DataCustodianVuln {
    mapping(uint256 => bytes) public records;
    event RecordStored(
        uint256 indexed id,
        DataCustodianType        ctype,
        DataCustodianAttackType  attack
    );
    event RecordDeleted(
        uint256 indexed id,
        DataCustodianAttackType  attack
    );

    /// ❌ anybody can store or overwrite any record
    function store(uint256 id, bytes calldata data) external {
        records[id] = data;
        emit RecordStored(id, DataCustodianType.Primary, DataCustodianAttackType.Tampering);
    }

    /// ❌ anybody can delete any record
    function remove(uint256 id) external {
        delete records[id];
        emit RecordDeleted(id, DataCustodianAttackType.Deletion);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB
///    • demonstrates unauthorized overwrite and deletion
///─────────────────────────────────────────────────────────────────────────────
contract Attack_DataCustodian {
    DataCustodianVuln public target;
    constructor(DataCustodianVuln _t) { target = _t; }

    /// overwrite victim’s data
    function spoof(uint256 id, bytes calldata fake) external {
        target.store(id, fake);
    }

    /// wipe out a record
    function wipe(uint256 id) external {
        target.remove(id);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE CUSTODIAN (OWNER‑ONLY, IMMUTABLE ONCE)
///    • Defense: AccessControl + ImmutableRecord
///─────────────────────────────────────────────────────────────────────────────
contract DataCustodianSafe {
    mapping(uint256 => bytes)    private records;
    mapping(uint256 => bool)     private _set;
    address public owner;
    event RecordStored(
        uint256 indexed id,
        DataCustodianType        ctype,
        DataCustodianDefenseType defense
    );

    constructor() {
        owner = msg.sender;
    }

    /// ✅ only owner may store, and only once per id
    function store(uint256 id, bytes calldata data) external {
        if (msg.sender != owner)         revert DC__NotOwner();
        if (_set[id])                    revert DC__AlreadySet();
        _set[id] = true;
        records[id] = data;
        emit RecordStored(id, DataCustodianType.Primary, DataCustodianDefenseType.ImmutableRecord);
    }

    function retrieve(uint256 id) external view returns (bytes memory) {
        if (!_set[id]) revert DC__NoData();
        return records[id];
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) ADVANCED SAFE (RATE‑LIMITED + ENCRYPTION)
//     • Defense: RateLimit + Encryption flag
///─────────────────────────────────────────────────────────────────────────────
contract DataCustodianSafeAdvanced {
    mapping(uint256 => bytes)    private records;
    mapping(uint256 => bool)     private _set;
    mapping(address => uint256)  public lastBlock;
    mapping(address => uint256)  public countInBlock;
    address public owner;
    uint256 public constant MAX_PER_BLOCK = 5;

    event RecordStored(
        uint256 indexed id,
        DataCustodianType        ctype,
        DataCustodianDefenseType defense
    );

    error DC__TooMany();

    constructor() {
        owner = msg.sender;
    }

    /// ✅ only owner, rate‑limit per block and require encrypted data (first byte = 0x01)
    function store(uint256 id, bytes calldata data) external {
        if (msg.sender != owner) revert DC__NotOwner();

        // rate‑limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender] = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender]++;
        if (countInBlock[msg.sender] > MAX_PER_BLOCK) revert DC__TooMany();

        // encryption flag check
        if (data.length == 0 || data[0] != 0x01) revert DC__NotEncrypted();

        require(!_set[id], "immutable");
        _set[id] = true;
        records[id] = data;
        emit RecordStored(id, DataCustodianType.Primary, DataCustodianDefenseType.Encryption);
    }

    function retrieve(uint256 id) external view returns (bytes memory) {
        if (!_set[id]) revert DC__NoData();
        return records[id];
    }
}
