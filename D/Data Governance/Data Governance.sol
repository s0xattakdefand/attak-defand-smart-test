// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DataGovernanceSecuritySuite.sol
/// @notice On‐chain analogues for “Data Governance” security patterns:
///   Types: PolicyDefinition, ComplianceCheck, StakeholderAssignment, AuditTrail  
///   AttackTypes: UnauthorizedPolicyChange, BypassCompliance, PrivilegeEscalation, ReplayPolicy  
///   DefenseTypes: AccessControl, IntegrityCheck, RateLimit, SignatureValidation, AuditLogging

enum DGType               { PolicyDefinition, ComplianceCheck, StakeholderAssignment, AuditTrail }
enum DGAttackType         { UnauthorizedPolicyChange, BypassCompliance, PrivilegeEscalation, ReplayPolicy }
enum DGDefenseType        { AccessControl, IntegrityCheck, RateLimit, SignatureValidation, AuditLogging }

error DG__NotAuthorized();
error DG__InvalidInput();
error DG__TooManyRequests();
error DG__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE GOVERNANCE MANAGER
//    • ❌ no checks: anyone may define/update/read policies → UnauthorizedPolicyChange, ReplayPolicy
////////////////////////////////////////////////////////////////////////////////
contract DataGovernanceVuln {
    mapping(uint256 => string) public policies;

    event PolicyDefined(
        address indexed who,
        uint256           policyId,
        DGType            dtype,
        DGAttackType      attack
    );
    event PolicyUpdated(
        address indexed who,
        uint256           policyId,
        DGType            dtype,
        DGAttackType      attack
    );
    event PolicyRead(
        address indexed who,
        uint256           policyId,
        DGType            dtype,
        DGAttackType      attack
    );

    function definePolicy(uint256 policyId, string calldata policy, DGType dtype) external {
        policies[policyId] = policy;
        emit PolicyDefined(msg.sender, policyId, dtype, DGAttackType.UnauthorizedPolicyChange);
    }

    function updatePolicy(uint256 policyId, string calldata policy, DGType dtype) external {
        policies[policyId] = policy;
        emit PolicyUpdated(msg.sender, policyId, dtype, DGAttackType.BypassCompliance);
    }

    function readPolicy(uint256 policyId, DGType dtype) external view returns (string memory) {
        emit PolicyRead(msg.sender, policyId, dtype, DGAttackType.ReplayPolicy);
        return policies[policyId];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates unauthorized define/update, replay
////////////////////////////////////////////////////////////////////////////////
contract Attack_DataGovernance {
    DataGovernanceVuln public target;
    uint256 public lastId;
    string  public lastPolicy;

    constructor(DataGovernanceVuln _t) {
        target = _t;
    }

    function spoofDefine(uint256 id, string calldata policy) external {
        target.definePolicy(id, policy, DGType.PolicyDefinition);
        lastId      = id;
        lastPolicy  = policy;
    }

    function tamper(uint256 id, string calldata policy) external {
        target.updatePolicy(id, policy, DGType.ComplianceCheck);
    }

    function replayRead() external {
        target.readPolicy(lastId, DGType.AuditTrail);
    }

    function replayDefine() external {
        target.definePolicy(lastId, lastPolicy, DGType.StakeholderAssignment);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may define/update/read
////////////////////////////////////////////////////////////////////////////////
contract DataGovernanceSafeAccess {
    mapping(uint256 => string) public policies;
    address public owner;

    event PolicyDefined(
        address indexed who,
        uint256           policyId,
        DGType            dtype,
        DGDefenseType     defense
    );
    event PolicyUpdated(
        address indexed who,
        uint256           policyId,
        DGType            dtype,
        DGDefenseType     defense
    );
    event PolicyRead(
        address indexed who,
        uint256           policyId,
        DGType            dtype,
        DGDefenseType     defense
    );

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert DG__NotAuthorized();
        _;
    }

    function definePolicy(uint256 policyId, string calldata policy, DGType dtype)
        external onlyOwner
    {
        policies[policyId] = policy;
        emit PolicyDefined(msg.sender, policyId, dtype, DGDefenseType.AccessControl);
    }

    function updatePolicy(uint256 policyId, string calldata policy, DGType dtype)
        external onlyOwner
    {
        policies[policyId] = policy;
        emit PolicyUpdated(msg.sender, policyId, dtype, DGDefenseType.AccessControl);
    }

    function readPolicy(uint256 policyId, DGType dtype)
        external view onlyOwner returns (string memory)
    {
        emit PolicyRead(msg.sender, policyId, dtype, DGDefenseType.AccessControl);
        return policies[policyId];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH VALIDATION & RATE LIMIT
//    • ✅ Defense: IntegrityCheck – require nonempty policy  
//               RateLimit      – cap ops per block
////////////////////////////////////////////////////////////////////////////////
contract DataGovernanceSafeValidate {
    mapping(uint256 => string) public policies;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public opsInBlock;
    uint256 public constant MAX_OPS = 5;

    event PolicyDefined(
        address indexed who,
        uint256           policyId,
        DGType            dtype,
        DGDefenseType     defense
    );
    event PolicyUpdated(
        address indexed who,
        uint256           policyId,
        DGType            dtype,
        DGDefenseType     defense
    );
    event PolicyRead(
        address indexed who,
        uint256           policyId,
        DGType            dtype,
        DGDefenseType     defense
    );

    error DG__InvalidInput();
    error DG__TooManyRequests();

    modifier rateLimit() {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]   = block.number;
            opsInBlock[msg.sender]  = 0;
        }
        opsInBlock[msg.sender]++;
        if (opsInBlock[msg.sender] > MAX_OPS) revert DG__TooManyRequests();
        _;
    }

    function definePolicy(uint256 policyId, string calldata policy, DGType dtype)
        external rateLimit
    {
        if (bytes(policy).length == 0) revert DG__InvalidInput();
        policies[policyId] = policy;
        emit PolicyDefined(msg.sender, policyId, dtype, DGDefenseType.IntegrityCheck);
    }

    function updatePolicy(uint256 policyId, string calldata policy, DGType dtype)
        external rateLimit
    {
        if (bytes(policy).length == 0) revert DG__InvalidInput();
        policies[policyId] = policy;
        emit PolicyUpdated(msg.sender, policyId, dtype, DGDefenseType.IntegrityCheck);
    }

    function readPolicy(uint256 policyId, DGType dtype)
        external rateLimit returns (string memory)
    {
        emit PolicyRead(msg.sender, policyId, dtype, DGDefenseType.RateLimit);
        return policies[policyId];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & AUDIT LOGGING
//    • ✅ Defense: SignatureValidation – require admin‐signed ops  
//               AuditLogging      – record each action
////////////////////////////////////////////////////////////////////////////////
contract DataGovernanceSafeAdvanced {
    mapping(uint256 => string) public policies;
    address public signer;

    event PolicyDefined(
        address indexed who,
        uint256           policyId,
        DGType            dtype,
        DGDefenseType     defense
    );
    event PolicyUpdated(
        address indexed who,
        uint256           policyId,
        DGType            dtype,
        DGDefenseType     defense
    );
    event PolicyRead(
        address indexed who,
        uint256           policyId,
        DGType            dtype,
        DGDefenseType     defense
    );
    event AuditLog(
        address indexed who,
        string            action,
        uint256           policyId,
        DGDefenseType     defense
    );

    error DG__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function definePolicy(
        uint256 policyId,
        string calldata policy,
        DGType dtype,
        bytes calldata sig
    ) external {
        bytes32 h = keccak256(abi.encodePacked("DEFINE", msg.sender, policyId, policy, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DG__InvalidSignature();

        policies[policyId] = policy;
        emit PolicyDefined(msg.sender, policyId, dtype, DGDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "definePolicy", policyId, DGDefenseType.AuditLogging);
    }

    function updatePolicy(
        uint256 policyId,
        string calldata policy,
        DGType dtype,
        bytes calldata sig
    ) external {
        bytes32 h = keccak256(abi.encodePacked("UPDATE", msg.sender, policyId, policy, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DG__InvalidSignature();

        policies[policyId] = policy;
        emit PolicyUpdated(msg.sender, policyId, dtype, DGDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "updatePolicy", policyId, DGDefenseType.AuditLogging);
    }

    function readPolicy(
        uint256 policyId,
        DGType dtype,
        bytes calldata sig
    ) external returns (string memory) {
        bytes32 h = keccak256(abi.encodePacked("READ", msg.sender, policyId, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DG__InvalidSignature();

        string memory p = policies[policyId];
        emit PolicyRead(msg.sender, policyId, dtype, DGDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "readPolicy", policyId, DGDefenseType.AuditLogging);
        return p;
    }
}
