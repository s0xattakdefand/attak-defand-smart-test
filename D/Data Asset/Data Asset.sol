// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DataAssetSecuritySuite.sol
/// @notice On‐chain analogues for “Data Asset” security patterns:
///   Types: Classified, Public, Restricted, Regulatory  
///   AttackTypes: UnauthorizedExfiltration, Tampering, Spoofing, Leak  
///   DefenseTypes: Encryption, AccessControl, IntegrityCheck, AuditLogging, SignatureValidation

enum DataAssetType        { Classified, Public, Restricted, Regulatory }
enum DataAssetAttackType  { UnauthorizedExfiltration, Tampering, Spoofing, Leak }
enum DataAssetDefenseType { Encryption, AccessControl, IntegrityCheck, AuditLogging, SignatureValidation }

error DA__NotAuthorized();
error DA__InvalidInput();
error DA__TooManyRequests();
error DA__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE DATA ASSET MANAGER
//    • ❌ no checks: anyone may register/update/read sensitive data → Leak/Tampering
////////////////////////////////////////////////////////////////////////////////
contract DataAssetVuln {
    mapping(uint256 => string) public assets;

    event AssetRegistered(
        address indexed who,
        uint256           assetId,
        DataAssetType     atype,
        DataAssetAttackType attack
    );
    event AssetUpdated(
        address indexed who,
        uint256           assetId,
        DataAssetType     atype,
        DataAssetAttackType attack
    );
    event AssetAccessed(
        address indexed who,
        uint256           assetId,
        DataAssetType     atype,
        DataAssetAttackType attack
    );

    function registerAsset(uint256 assetId, string calldata data, DataAssetType atype) external {
        assets[assetId] = data;
        emit AssetRegistered(msg.sender, assetId, atype, DataAssetAttackType.Spoofing);
    }

    function updateAsset(uint256 assetId, string calldata data, DataAssetType atype) external {
        assets[assetId] = data;
        emit AssetUpdated(msg.sender, assetId, atype, DataAssetAttackType.Tampering);
    }

    function readAsset(uint256 assetId, DataAssetType atype) external view returns (string memory) {
        emit AssetAccessed(msg.sender, assetId, atype, DataAssetAttackType.UnauthorizedExfiltration);
        return assets[assetId];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates unauthorized exfiltration, spoof, tamper, leak
////////////////////////////////////////////////////////////////////////////////
contract Attack_DataAsset {
    DataAssetVuln public target;
    uint256 public lastAssetId;
    string  public lastData;

    constructor(DataAssetVuln _t) { target = _t; }

    function spoofRegister(uint256 assetId, string calldata fake) external {
        target.registerAsset(assetId, fake, DataAssetType.Classified);
        lastAssetId = assetId;
        lastData = fake;
    }

    function tamper(uint256 assetId, string calldata fake) external {
        target.updateAsset(assetId, fake, DataAssetType.Restricted);
    }

    function leak(uint256 assetId) external {
        lastData = target.readAsset(assetId, DataAssetType.Classified);
    }

    function replaySpoof() external {
        target.registerAsset(lastAssetId, lastData, DataAssetType.Classified);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may register/update/read
////////////////////////////////////////////////////////////////////////////////
contract DataAssetSafeAccess {
    mapping(uint256 => string) public assets;
    address public owner;

    event AssetRegistered(
        address indexed who,
        uint256           assetId,
        DataAssetType     atype,
        DataAssetDefenseType defense
    );
    event AssetUpdated(
        address indexed who,
        uint256           assetId,
        DataAssetType     atype,
        DataAssetDefenseType defense
    );
    event AssetAccessed(
        address indexed who,
        uint256           assetId,
        DataAssetType     atype,
        DataAssetDefenseType defense
    );

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert DA__NotAuthorized();
        _;
    }

    function registerAsset(uint256 assetId, string calldata data, DataAssetType atype) external onlyOwner {
        assets[assetId] = data;
        emit AssetRegistered(msg.sender, assetId, atype, DataAssetDefenseType.AccessControl);
    }

    function updateAsset(uint256 assetId, string calldata data, DataAssetType atype) external onlyOwner {
        assets[assetId] = data;
        emit AssetUpdated(msg.sender, assetId, atype, DataAssetDefenseType.AccessControl);
    }

    function readAsset(uint256 assetId, DataAssetType atype) external view onlyOwner returns (string memory) {
        emit AssetAccessed(msg.sender, assetId, atype, DataAssetDefenseType.AccessControl);
        return assets[assetId];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH VALIDATION & RATE LIMIT
//    • ✅ Defense: IntegrityCheck – require nonempty data  
//               RateLimit       – cap ops per block
////////////////////////////////////////////////////////////////////////////////
contract DataAssetSafeValidate {
    mapping(uint256 => string) public assets;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public opsInBlock;
    uint256 public constant MAX_OPS = 5;

    event AssetRegistered(
        address indexed who,
        uint256           assetId,
        DataAssetType     atype,
        DataAssetDefenseType defense
    );
    event AssetUpdated(
        address indexed who,
        uint256           assetId,
        DataAssetType     atype,
        DataAssetDefenseType defense
    );
    event AssetAccessed(
        address indexed who,
        uint256           assetId,
        DataAssetType     atype,
        DataAssetDefenseType defense
    );

    error DA__InvalidInput();
    error DA__TooManyRequests();

    modifier rateLimit() {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            opsInBlock[msg.sender] = 0;
        }
        opsInBlock[msg.sender]++;
        if (opsInBlock[msg.sender] > MAX_OPS) revert DA__TooManyRequests();
        _;
    }

    function registerAsset(uint256 assetId, string calldata data, DataAssetType atype) external rateLimit {
        if (bytes(data).length == 0) revert DA__InvalidInput();
        assets[assetId] = data;
        emit AssetRegistered(msg.sender, assetId, atype, DataAssetDefenseType.IntegrityCheck);
    }

    function updateAsset(uint256 assetId, string calldata data, DataAssetType atype) external rateLimit {
        if (bytes(data).length == 0) revert DA__InvalidInput();
        assets[assetId] = data;
        emit AssetUpdated(msg.sender, assetId, atype, DataAssetDefenseType.IntegrityCheck);
    }

    function readAsset(uint256 assetId, DataAssetType atype) external rateLimit returns (string memory) {
        string memory d = assets[assetId];
        emit AssetAccessed(msg.sender, assetId, atype, DataAssetDefenseType.RateLimit);
        return d;
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & AUDIT LOGGING
//    • ✅ Defense: SignatureValidation – require admin‐signed ops  
//               AuditLogging      – record each action
////////////////////////////////////////////////////////////////////////////////
contract DataAssetSafeAdvanced {
    mapping(uint256 => string) public assets;
    address public signer;

    event AssetRegistered(
        address indexed who,
        uint256           assetId,
        DataAssetType     atype,
        DataAssetDefenseType defense
    );
    event AssetUpdated(
        address indexed who,
        uint256           assetId,
        DataAssetType     atype,
        DataAssetDefenseType defense
    );
    event AssetAccessed(
        address indexed who,
        uint256           assetId,
        DataAssetType     atype,
        DataAssetDefenseType defense
    );
    event AuditLog(
        address indexed who,
        string            action,
        uint256           assetId,
        DataAssetDefenseType defense
    );

    error DA__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function registerAsset(
        uint256 assetId,
        string calldata data,
        DataAssetType atype,
        bytes calldata sig
    ) external {
        bytes32 h = keccak256(abi.encodePacked("REGISTER", assetId, data, atype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DA__InvalidSignature();

        assets[assetId] = data;
        emit AssetRegistered(msg.sender, assetId, atype, DataAssetDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "registerAsset", assetId, DataAssetDefenseType.AuditLogging);
    }

    function updateAsset(
        uint256 assetId,
        string calldata data,
        DataAssetType atype,
        bytes calldata sig
    ) external {
        bytes32 h = keccak256(abi.encodePacked("UPDATE", assetId, data, atype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DA__InvalidSignature();

        assets[assetId] = data;
        emit AssetUpdated(msg.sender, assetId, atype, DataAssetDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "updateAsset", assetId, DataAssetDefenseType.AuditLogging);
    }

    function readAsset(
        uint256 assetId,
        DataAssetType atype,
        bytes calldata sig
    ) external returns (string memory) {
        bytes32 h = keccak256(abi.encodePacked("READ", assetId, atype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DA__InvalidSignature();

        string memory d = assets[assetId];
        emit AssetAccessed(msg.sender, assetId, atype, DataAssetDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "readAsset", assetId, DataAssetDefenseType.AuditLogging);
        return d;
    }
}
