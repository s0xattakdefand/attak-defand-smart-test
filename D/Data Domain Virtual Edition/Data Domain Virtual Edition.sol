// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DataDomainVirtualEditionSecuritySuite.sol
/// @notice On‐chain analogues for “Data Domain Virtual Edition” patterns:
///   Types: LocalBackup, SnapshotBackup, OffsiteReplication, VirtualEdition  
///   AttackTypes: RansomwareEncryption, UnauthorizedDeletion, ReplayRestore, DataCorruption  
///   DefenseTypes: ImmutableBackup, EncryptionAtRest, AccessControl, IntegrityCheck, SignatureValidation

enum DDVType               { LocalBackup, SnapshotBackup, OffsiteReplication, VirtualEdition }
enum DDVAttackType         { RansomwareEncryption, UnauthorizedDeletion, ReplayRestore, DataCorruption }
enum DDVDefenseType        { ImmutableBackup, EncryptionAtRest, AccessControl, IntegrityCheck, SignatureValidation }

error DDV__NotAuthorized();
error DDV__InvalidInput();
error DDV__TooManyRequests();
error DDV__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE BACKUP MANAGER
//    • ❌ no checks: anyone may store/delete/restore → UnauthorizedDeletion, DataCorruption
////////////////////////////////////////////////////////////////////////////////
contract DataDomainVuln {
    mapping(uint256 => bytes) public backups;
    event BackupStored(address indexed who, uint256 id, DDVType dtype, DDVAttackType attack);
    event BackupDeleted(address indexed who, uint256 id, DDVType dtype, DDVAttackType attack);
    event BackupRestored(address indexed who, uint256 id, DDVType dtype, DDVAttackType attack);

    function storeBackup(uint256 id, bytes calldata data, DDVType dtype) external {
        backups[id] = data;
        emit BackupStored(msg.sender, id, dtype, DDVAttackType.DataCorruption);
    }

    function deleteBackup(uint256 id, DDVType dtype) external {
        delete backups[id];
        emit BackupDeleted(msg.sender, id, dtype, DDVAttackType.UnauthorizedDeletion);
    }

    function restoreBackup(uint256 id, DDVType dtype) external view returns (bytes memory) {
        emit BackupRestored(msg.sender, id, dtype, DDVAttackType.ReplayRestore);
        return backups[id];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates ransomware, deletion, corruption, replay restore
////////////////////////////////////////////////////////////////////////////////
contract Attack_DDV {
    DataDomainVuln public target;
    uint256 public lastId;
    bytes  public lastData;

    constructor(DataDomainVuln _t) { target = _t; }

    function ransomwareEncrypt(uint256 id, bytes calldata fake) external {
        target.storeBackup(id, fake, DDVType.VirtualEdition);
    }

    function unauthorizedDelete(uint256 id) external {
        target.deleteBackup(id, DDVType.SnapshotBackup);
    }

    function corruptData(uint256 id, bytes calldata fake) external {
        target.storeBackup(id, fake, DDVType.LocalBackup);
    }

    function replayRestore(uint256 id) external {
        bytes memory d = target.restoreBackup(id, DDVType.OffsiteReplication);
        lastId = id; lastData = d;
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may operate
////////////////////////////////////////////////////////////////////////////////
contract DataDomainSafeAccess {
    mapping(uint256 => bytes) public backups;
    address public owner;
    event BackupStored(address indexed who, uint256 id, DDVType dtype, DDVDefenseType defense);
    event BackupDeleted(address indexed who, uint256 id, DDVType dtype, DDVDefenseType defense);
    event BackupRestored(address indexed who, uint256 id, DDVType dtype, DDVDefenseType defense);

    constructor() { owner = msg.sender; }
    modifier onlyOwner() {
        if (msg.sender != owner) revert DDV__NotAuthorized();
        _;
    }

    function storeBackup(uint256 id, bytes calldata data, DDVType dtype) external onlyOwner {
        backups[id] = data;
        emit BackupStored(msg.sender, id, dtype, DDVDefenseType.AccessControl);
    }

    function deleteBackup(uint256 id, DDVType dtype) external onlyOwner {
        delete backups[id];
        emit BackupDeleted(msg.sender, id, dtype, DDVDefenseType.AccessControl);
    }

    function restoreBackup(uint256 id, DDVType dtype) external view onlyOwner returns (bytes memory) {
        emit BackupRestored(msg.sender, id, dtype, DDVDefenseType.AccessControl);
        return backups[id];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH VALIDATION & RATE LIMIT
//    • ✅ Defense: IntegrityCheck – require nonempty data  
//               RateLimit       – cap ops per block
////////////////////////////////////////////////////////////////////////////////
contract DataDomainSafeValidate {
    mapping(uint256 => bytes) public backups;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public opsInBlock;
    uint256 public constant MAX_OPS = 4;

    event BackupStored(address indexed who, uint256 id, DDVType dtype, DDVDefenseType defense);
    event BackupDeleted(address indexed who, uint256 id, DDVType dtype, DDVDefenseType defense);
    event BackupRestored(address indexed who, uint256 id, DDVType dtype, DDVDefenseType defense);

    error DDV__InvalidInput();
    error DDV__TooManyRequests();

    modifier rateLimit() {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]   = block.number;
            opsInBlock[msg.sender]  = 0;
        }
        opsInBlock[msg.sender]++;
        if (opsInBlock[msg.sender] > MAX_OPS) revert DDV__TooManyRequests();
        _;
    }

    function storeBackup(uint256 id, bytes calldata data, DDVType dtype) external rateLimit {
        if (data.length == 0) revert DDV__InvalidInput();
        backups[id] = data;
        emit BackupStored(msg.sender, id, dtype, DDVDefenseType.IntegrityCheck);
    }

    function deleteBackup(uint256 id, DDVType dtype) external rateLimit {
        delete backups[id];
        emit BackupDeleted(msg.sender, id, dtype, DDVDefenseType.RateLimit);
    }

    function restoreBackup(uint256 id, DDVType dtype) external rateLimit returns (bytes memory) {
        emit BackupRestored(msg.sender, id, dtype, DDVDefenseType.RateLimit);
        return backups[id];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & AUDIT LOGGING
//    • ✅ Defense: SignatureValidation – require signed ops  
//               AuditLogging       – record each action
////////////////////////////////////////////////////////////////////////////////
contract DataDomainSafeAdvanced {
    mapping(uint256 => bytes) public backups;
    address public signer;
    event BackupStored(address indexed who, uint256 id, DDVType dtype, DDVDefenseType defense);
    event BackupDeleted(address indexed who, uint256 id, DDVType dtype, DDVDefenseType defense);
    event BackupRestored(address indexed who, uint256 id, DDVType dtype, DDVDefenseType defense);
    event AuditLog(address indexed who, string action, uint256 id, DDVDefenseType defense);

    error DDV__InvalidSignature();

    constructor(address _signer) { signer = _signer; }

    function storeBackup(
        uint256 id,
        bytes calldata data,
        DDVType dtype,
        bytes calldata sig
    ) external {
        bytes32 h = keccak256(abi.encodePacked("STORE", msg.sender, id, data, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DDV__InvalidSignature();

        backups[id] = data;
        emit BackupStored(msg.sender, id, dtype, DDVDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "storeBackup", id, DDVDefenseType.AuditLogging);
    }

    function deleteBackup(
        uint256 id,
        DDVType dtype,
        bytes calldata sig
    ) external {
        bytes32 h = keccak256(abi.encodePacked("DELETE", msg.sender, id, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DDV__InvalidSignature();

        delete backups[id];
        emit BackupDeleted(msg.sender, id, dtype, DDVDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "deleteBackup", id, DDVDefenseType.AuditLogging);
    }

    function restoreBackup(
        uint256 id,
        DDVType dtype,
        bytes calldata sig
    ) external returns (bytes memory) {
        bytes32 h = keccak256(abi.encodePacked("RESTORE", msg.sender, id, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DDV__InvalidSignature();

        bytes memory data = backups[id];
        emit BackupRestored(msg.sender, id, dtype, DDVDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "restoreBackup", id, DDVDefenseType.AuditLogging);
        return data;
    }
}
