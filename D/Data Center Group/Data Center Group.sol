// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DataCenterGroupSecuritySuite.sol
/// @notice On‐chain analogues for “Data Center Group” security patterns:
///   Types: SingleDC, MultiDCGroup, HybridDC, EdgeDCGroup  
///   AttackTypes: UnauthorizedAccess, Misconfiguration, DDoS, DataExfiltration  
///   DefenseTypes: AccessControl, NetworkSegmentation, RateLimit, Monitoring, SignatureValidation

enum DCGType                { SingleDC, MultiDCGroup, HybridDC, EdgeDCGroup }
enum DCGAttackType          { UnauthorizedAccess, Misconfiguration, DDoS, DataExfiltration }
enum DCGDefenseType         { AccessControl, NetworkSegmentation, RateLimit, Monitoring, SignatureValidation }

error DCG__NotAuthorized();
error DCG__InvalidInput();
error DCG__TooManyRequests();
error DCG__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE MANAGER
//    • ❌ no checks: anyone may register/update/read groups → UnauthorizedAccess/DataExfiltration
////////////////////////////////////////////////////////////////////////////////
contract DataCenterGroupVuln {
    mapping(uint256 => string) public groups;

    event GroupRegistered(
        address indexed who,
        uint256           groupId,
        DCGType           dtype,
        DCGAttackType     attack
    );
    event GroupUpdated(
        address indexed who,
        uint256           groupId,
        DCGType           dtype,
        DCGAttackType     attack
    );
    event GroupAccessed(
        address indexed who,
        uint256           groupId,
        DCGType           dtype,
        DCGAttackType     attack
    );

    function registerGroup(uint256 groupId, string calldata info, DCGType dtype) external {
        groups[groupId] = info;
        emit GroupRegistered(msg.sender, groupId, dtype, DCGAttackType.Misconfiguration);
    }

    function updateGroup(uint256 groupId, string calldata info, DCGType dtype) external {
        groups[groupId] = info;
        emit GroupUpdated(msg.sender, groupId, dtype, DCGAttackType.Misconfiguration);
    }

    function getGroup(uint256 groupId, DCGType dtype) external view returns (string memory) {
        emit GroupAccessed(msg.sender, groupId, dtype, DCGAttackType.DataExfiltration);
        return groups[groupId];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates unauthorized access, tampering, DDoS, data exfiltration
////////////////////////////////////////////////////////////////////////////////
contract Attack_DataCenterGroup {
    DataCenterGroupVuln public target;
    uint256 public lastGroupId;
    string  public lastInfo;

    constructor(DataCenterGroupVuln _t) {
        target = _t;
    }

    function spoofRegister(uint256 groupId, string calldata fake) external {
        target.registerGroup(groupId, fake, DCGType.SingleDC);
        lastGroupId = groupId;
        lastInfo    = fake;
    }

    function tamper(uint256 groupId, string calldata fake) external {
        target.updateGroup(groupId, fake, DCGType.HybridDC);
    }

    function exfiltrate(uint256 groupId) external {
        lastInfo = target.getGroup(groupId, DCGType.MultiDCGroup);
    }

    function replaySpoof() external {
        target.registerGroup(lastGroupId, lastInfo, DCGType.EdgeDCGroup);
    }

    function floodGet(uint256 groupId, uint256 times) external {
        for (uint i = 0; i < times; i++) {
            target.getGroup(groupId, DCGType.HybridDC);
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may register/update/read
////////////////////////////////////////////////////////////////////////////////
contract DataCenterGroupSafeAccess {
    mapping(uint256 => string) public groups;
    address public owner;

    event GroupRegistered(
        address indexed who,
        uint256           groupId,
        DCGType           dtype,
        DCGDefenseType    defense
    );
    event GroupUpdated(
        address indexed who,
        uint256           groupId,
        DCGType           dtype,
        DCGDefenseType    defense
    );
    event GroupAccessed(
        address indexed who,
        uint256           groupId,
        DCGType           dtype,
        DCGDefenseType    defense
    );

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert DCG__NotAuthorized();
        _;
    }

    function registerGroup(uint256 groupId, string calldata info, DCGType dtype) external onlyOwner {
        groups[groupId] = info;
        emit GroupRegistered(msg.sender, groupId, dtype, DCGDefenseType.AccessControl);
    }

    function updateGroup(uint256 groupId, string calldata info, DCGType dtype) external onlyOwner {
        groups[groupId] = info;
        emit GroupUpdated(msg.sender, groupId, dtype, DCGDefenseType.AccessControl);
    }

    function getGroup(uint256 groupId, DCGType dtype) external view onlyOwner returns (string memory) {
        emit GroupAccessed(msg.sender, groupId, dtype, DCGDefenseType.AccessControl);
        return groups[groupId];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH VALIDATION & RATE LIMIT
//    • ✅ Defense: IntegrityCheck – require nonempty info  
//               RateLimit       – cap operations per block
////////////////////////////////////////////////////////////////////////////////
contract DataCenterGroupSafeValidate {
    mapping(uint256 => string) public groups;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public opsInBlock;
    uint256 public constant MAX_OPS = 5;

    event GroupRegistered(
        address indexed who,
        uint256           groupId,
        DCGType           dtype,
        DCGDefenseType    defense
    );
    event GroupUpdated(
        address indexed who,
        uint256           groupId,
        DCGType           dtype,
        DCGDefenseType    defense
    );
    event GroupAccessed(
        address indexed who,
        uint256           groupId,
        DCGType           dtype,
        DCGDefenseType    defense
    );

    error DCG__InvalidInput();
    error DCG__TooManyRequests();

    modifier rateLimit() {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            opsInBlock[msg.sender] = 0;
        }
        opsInBlock[msg.sender]++;
        if (opsInBlock[msg.sender] > MAX_OPS) revert DCG__TooManyRequests();
        _;
    }

    function registerGroup(uint256 groupId, string calldata info, DCGType dtype) external rateLimit {
        if (bytes(info).length == 0) revert DCG__InvalidInput();
        groups[groupId] = info;
        emit GroupRegistered(msg.sender, groupId, dtype, DCGDefenseType.IntegrityCheck);
    }

    function updateGroup(uint256 groupId, string calldata info, DCGType dtype) external rateLimit {
        if (bytes(info).length == 0) revert DCG__InvalidInput();
        groups[groupId] = info;
        emit GroupUpdated(msg.sender, groupId, dtype, DCGDefenseType.IntegrityCheck);
    }

    function getGroup(uint256 groupId, DCGType dtype) external rateLimit returns (string memory) {
        string memory info = groups[groupId];
        emit GroupAccessed(msg.sender, groupId, dtype, DCGDefenseType.RateLimit);
        return info;
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & AUDIT LOGGING
//    • ✅ Defense: SignatureValidation – require admin‐signed ops  
//               AuditLogging      – record each action
////////////////////////////////////////////////////////////////////////////////
contract DataCenterGroupSafeAdvanced {
    mapping(uint256 => string) public groups;
    address public signer;

    event GroupRegistered(
        address indexed who,
        uint256           groupId,
        DCGType           dtype,
        DCGDefenseType    defense
    );
    event GroupUpdated(
        address indexed who,
        uint256           groupId,
        DCGType           dtype,
        DCGDefenseType    defense
    );
    event GroupAccessed(
        address indexed who,
        uint256           groupId,
        DCGType           dtype,
        DCGDefenseType    defense
    );
    event AuditLog(
        address indexed who,
        string            action,
        uint256           groupId,
        DCGDefenseType    defense
    );

    error DCG__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function registerGroup(
        uint256 groupId,
        string calldata info,
        DCGType dtype,
        bytes calldata sig
    ) external {
        bytes32 h = keccak256(abi.encodePacked("REGISTER", groupId, info, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DCG__InvalidSignature();

        groups[groupId] = info;
        emit GroupRegistered(msg.sender, groupId, dtype, DCGDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "registerGroup", groupId, DCGDefenseType.AuditLogging);
    }

    function updateGroup(
        uint256 groupId,
        string calldata info,
        DCGType dtype,
        bytes calldata sig
    ) external {
        bytes32 h = keccak256(abi.encodePacked("UPDATE", groupId, info, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DCG__InvalidSignature();

        groups[groupId] = info;
        emit GroupUpdated(msg.sender, groupId, dtype, DCGDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "updateGroup", groupId, DCGDefenseType.AuditLogging);
    }

    function getGroup(
        uint256 groupId,
        DCGType dtype,
        bytes calldata sig
    ) external returns (string memory) {
        bytes32 h = keccak256(abi.encodePacked("GET", groupId, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DCG__InvalidSignature();

        string memory info = groups[groupId];
        emit GroupAccessed(msg.sender, groupId, dtype, DCGDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "getGroup", groupId, DCGDefenseType.AuditLogging);
        return info;
    }
}
