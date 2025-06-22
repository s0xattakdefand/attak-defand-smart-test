// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title ActionableFixesSuite.sol
/// @notice On‐chain analogues of “Actionable Fixes” remediation workflows:
///   Types: CodePatch, ConfigurationUpdate, PolicyChange, EmergencyHotfix  
///   AttackTypes: PatchBypass, ConfigTampering, DelayExploit, Rollback  
///   DefenseTypes: AccessControl, AutomatedTesting, Monitoring, RateLimit, SignatureValidation

enum ActionableFixType        { CodePatch, ConfigurationUpdate, PolicyChange, EmergencyHotfix }
enum ActionableFixAttackType  { PatchBypass, ConfigTampering, DelayExploit, Rollback }
enum ActionableFixDefenseType { AccessControl, AutomatedTesting, Monitoring, RateLimit, SignatureValidation }

error AFF__NotAuthorized();
error AFF__InvalidFix();
error AFF__TooManyRequests();
error AFF__InvalidSignature();

struct Fix {
    uint256    id;
    ActionableFixType ftype;
    string     description;
    bool       applied;
}

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE FIX MANAGER
//    • ❌ no checks: anyone may submit or apply fixes → PatchBypass
////////////////////////////////////////////////////////////////////////////////
contract ActionableFixVuln {
    mapping(uint256 => Fix) public fixes;

    event FixSubmitted(
        address indexed who,
        uint256           fixId,
        ActionableFixType ftype,
        ActionableFixAttackType attack
    );
    event FixApplied(
        address indexed who,
        uint256           fixId,
        ActionableFixType ftype,
        ActionableFixAttackType attack
    );

    function submitFix(uint256 fixId, ActionableFixType ftype, string calldata desc) external {
        fixes[fixId] = Fix(fixId, ftype, desc, false);
        emit FixSubmitted(msg.sender, fixId, ftype, ActionableFixAttackType.PatchBypass);
    }

    function applyFix(uint256 fixId) external {
        fixes[fixId].applied = true;
        emit FixApplied(msg.sender, fixId, fixes[fixId].ftype, ActionableFixAttackType.DelayExploit);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates bypass, tampering, rollback, replay
////////////////////////////////////////////////////////////////////////////////
contract Attack_ActionableFix {
    ActionableFixVuln public target;
    uint256 public lastId;

    constructor(ActionableFixVuln _t) {
        target = _t;
    }

    function bypassSubmit(uint256 fixId, string calldata desc) external {
        target.submitFix(fixId, ActionableFixType.PolicyChange, desc);
        lastId = fixId;
    }

    function tamperConfig(uint256 fixId) external {
        target.submitFix(fixId, ActionableFixType.ConfigurationUpdate, "malicious");
    }

    function replayApply() external {
        target.applyFix(lastId);
    }

    function rollback(uint256 fixId) external {
        // attacker reverts application
        target.applyFix(fixId);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may submit or apply
////////////////////////////////////////////////////////////////////////////////
contract ActionableFixSafeAccess {
    mapping(uint256 => Fix) public fixes;
    address public owner;

    event FixSubmitted(
        address indexed who,
        uint256           fixId,
        ActionableFixType ftype,
        ActionableFixDefenseType defense
    );
    event FixApplied(
        address indexed who,
        uint256           fixId,
        ActionableFixType ftype,
        ActionableFixDefenseType defense
    );

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert AFF__NotAuthorized();
        _;
    }

    function submitFix(uint256 fixId, ActionableFixType ftype, string calldata desc) external onlyOwner {
        fixes[fixId] = Fix(fixId, ftype, desc, false);
        emit FixSubmitted(msg.sender, fixId, ftype, ActionableFixDefenseType.AccessControl);
    }

    function applyFix(uint256 fixId) external onlyOwner {
        fixes[fixId].applied = true;
        emit FixApplied(msg.sender, fixId, fixes[fixId].ftype, ActionableFixDefenseType.AccessControl);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH AUTOMATED TESTING & RATE LIMIT
//    • ✅ Defense: AutomatedTesting – require test pass stub  
//               RateLimit        – cap operations per block
////////////////////////////////////////////////////////////////////////////////
contract ActionableFixSafeValidate {
    mapping(uint256 => Fix) public fixes;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public opsInBlock;
    uint256 public constant MAX_OPS = 3;

    event FixSubmitted(
        address indexed who,
        uint256           fixId,
        ActionableFixType ftype,
        ActionableFixDefenseType defense
    );
    event FixApplied(
        address indexed who,
        uint256           fixId,
        ActionableFixType ftype,
        ActionableFixDefenseType defense
    );

    error AFF__TooManyRequests();
    error AFF__InvalidFix();

    function _rateLimit() internal {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender] = block.number;
            opsInBlock[msg.sender] = 0;
        }
        opsInBlock[msg.sender]++;
        if (opsInBlock[msg.sender] > MAX_OPS) revert AFF__TooManyRequests();
    }

    function submitFix(uint256 fixId, ActionableFixType ftype, string calldata desc) external {
        _rateLimit();
        if (bytes(desc).length == 0) revert AFF__InvalidFix();
        fixes[fixId] = Fix(fixId, ftype, desc, false);
        emit FixSubmitted(msg.sender, fixId, ftype, ActionableFixDefenseType.AutomatedTesting);
    }

    function applyFix(uint256 fixId) external {
        _rateLimit();
        if (bytes(fixes[fixId].description).length == 0) revert AFF__InvalidFix();
        fixes[fixId].applied = true;
        emit FixApplied(msg.sender, fixId, fixes[fixId].ftype, ActionableFixDefenseType.RateLimit);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & MONITORING
//    • ✅ Defense: SignatureValidation – require admin signature  
//               Monitoring          – log every event
////////////////////////////////////////////////////////////////////////////////
contract ActionableFixSafeAdvanced {
    mapping(uint256 => Fix) public fixes;
    address public signer;

    event FixSubmitted(
        address indexed who,
        uint256           fixId,
        ActionableFixType ftype,
        ActionableFixDefenseType defense
    );
    event FixApplied(
        address indexed who,
        uint256           fixId,
        ActionableFixType ftype,
        ActionableFixDefenseType defense
    );
    event AuditLog(
        address indexed who,
        string            action,
        uint256           fixId,
        ActionableFixDefenseType defense
    );

    error AFF__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function submitFix(
        uint256 fixId,
        ActionableFixType ftype,
        string calldata desc,
        bytes calldata sig
    ) external {
        bytes32 h = keccak256(abi.encodePacked(fixId, ftype, desc));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert AFF__InvalidSignature();

        fixes[fixId] = Fix(fixId, ftype, desc, false);
        emit FixSubmitted(msg.sender, fixId, ftype, ActionableFixDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "submitFix", fixId, ActionableFixDefenseType.Monitoring);
    }

    function applyFix(
        uint256 fixId,
        bytes calldata sig
    ) external {
        bytes32 h = keccak256(abi.encodePacked("APPLY", fixId));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert AFF__InvalidSignature();

        fixes[fixId].applied = true;
        emit FixApplied(msg.sender, fixId, fixes[fixId].ftype, ActionableFixDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "applyFix", fixId, ActionableFixDefenseType.Monitoring);
    }
}
