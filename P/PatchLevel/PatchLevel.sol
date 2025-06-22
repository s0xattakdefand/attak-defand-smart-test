// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title PatchLevelSuite.sol
/// @notice On-chain analogues of “Patch Level” management patterns:
///   Types: Critical, Important, Moderate, Low  
///   AttackTypes: Exploitation, Rollback, Bypass, Tampering  
///   DefenseTypes: IntegrityVerification, AutomatedDeployment, AccessControl, AuditLogging  

enum PatchLevelType         { Critical, Important, Moderate, Low }
enum PatchLevelAttackType   { Exploitation, Rollback, Bypass, Tampering }
enum PatchLevelDefenseType  { IntegrityVerification, AutomatedDeployment, AccessControl, AuditLogging }

error PL__NotAuthorized();
error PL__InvalidSignature();
error PL__TooFrequent();
error PL__AlreadyExecuted();
error PL__ThresholdNotMet();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE PATCHER
//    • no checks: any caller may apply any patch → Exploitation
////////////////////////////////////////////////////////////////////////////////
contract PatchLevelVuln {
    mapping(bytes32 => string) public version; // softwareId → version
    event PatchApplied(
        address indexed who,
        bytes32 indexed softwareId,
        string          version,
        PatchLevelType  level,
        PatchLevelAttackType attack
    );

    function applyPatch(bytes32 softwareId, string calldata ver, PatchLevelType level) external {
        version[softwareId] = ver;
        emit PatchApplied(msg.sender, softwareId, ver, level, PatchLevelAttackType.Exploitation);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates rollback and patch bypass
////////////////////////////////////////////////////////////////////////////////
contract Attack_PatchLevel {
    PatchLevelVuln public target;
    mapping(bytes32 => string) public lastVersion;

    constructor(PatchLevelVuln _t) { target = _t; }

    function capture(bytes32 softwareId) external {
        lastVersion[softwareId] = target.version(softwareId);
    }

    function rollback(bytes32 softwareId, PatchLevelType level) external {
        // re-apply old version, bypassing intended update
        target.applyPatch(softwareId, lastVersion[softwareId], level);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH SIGNATURE VERIFICATION
//    • Defense: IntegrityVerification – require authority’s signed approval
////////////////////////////////////////////////////////////////////////////////
contract PatchLevelSafeIntegrity {
    address public authority;
    mapping(bytes32 => string) public version;
    event PatchApplied(
        address indexed who,
        bytes32 indexed softwareId,
        string          version,
        PatchLevelType  level,
        PatchLevelDefenseType defense
    );

    constructor(address _authority) {
        authority = _authority;
    }

    error PL__InvalidSignature();

    function applyPatch(
        bytes32 softwareId,
        string calldata ver,
        PatchLevelType level,
        bytes calldata sig
    ) external {
        // verify signature over (softwareId||ver||uint(level))
        bytes32 msgHash = keccak256(abi.encodePacked(softwareId, ver, uint(level)));
        bytes32 ethMsg  = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8, bytes32, bytes32));
        if (ecrecover(ethMsg, v, r, s) != authority) revert PL__InvalidSignature();

        version[softwareId] = ver;
        emit PatchApplied(msg.sender, softwareId, ver, level, PatchLevelDefenseType.IntegrityVerification);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH AUTOMATED DEPLOYMENT
//    • Defense: AutomatedDeployment – enforce interval between patches
////////////////////////////////////////////////////////////////////////////////
contract PatchLevelSafeAuto {
    mapping(bytes32 => string) public version;
    mapping(bytes32 => uint256) public lastPatch;
    uint256 public constant PATCH_INTERVAL = 1 days;

    event PatchApplied(
        bytes32 indexed softwareId,
        string          version,
        PatchLevelType  level,
        PatchLevelDefenseType defense
    );

    error PL__TooFrequent();

    function applyPatch(bytes32 softwareId, string calldata ver, PatchLevelType level) external {
        uint256 prev = lastPatch[softwareId];
        if (block.timestamp < prev + PATCH_INTERVAL) revert PL__TooFrequent();
        lastPatch[softwareId] = block.timestamp;
        version[softwareId] = ver;
        emit PatchApplied(softwareId, ver, level, PatchLevelDefenseType.AutomatedDeployment);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED MULTI-SIG & AUDIT LOGGING
//    • Defense: AccessControl + AuditLogging – require N-of-M approvals
////////////////////////////////////////////////////////////////////////////////
contract PatchLevelSafeAdvanced {
    address[] public approvers;
    uint256 public threshold;

    struct Proposal {
        bytes32 softwareId;
        string  ver;
        PatchLevelType level;
        uint256 approvals;
        bool    executed;
        mapping(address => bool) voted;
    }
    mapping(uint256 => Proposal) public proposals;
    uint256 public nextPid;

    event ProposalCreated(
        uint256 indexed pid,
        address indexed proposer,
        bytes32          softwareId,
        string           version,
        PatchLevelType   level,
        PatchLevelDefenseType defense
    );
    event ProposalApproved(
        uint256 indexed pid,
        address indexed approver,
        uint256          approvals,
        PatchLevelDefenseType defense
    );
    event PatchExecuted(
        uint256 indexed pid,
        bytes32          softwareId,
        string           version,
        PatchLevelType   level,
        PatchLevelDefenseType defense
    );

    error PL__NotApprover();
    error PL__AlreadyExecuted();
    error PL__ThresholdNotMet();

    constructor(address[] memory _approvers, uint256 _threshold) {
        require(_approvers.length >= _threshold, "threshold too high");
        approvers = _approvers;
        threshold = _threshold;
    }

    function isApprover(address who) internal view returns (bool) {
        for (uint i; i < approvers.length; i++) {
            if (approvers[i] == who) return true;
        }
        return false;
    }

    function proposePatch(bytes32 softwareId, string calldata ver, PatchLevelType level) external {
        require(isApprover(msg.sender), "not approver");
        Proposal storage p = proposals[nextPid];
        p.softwareId = softwareId;
        p.ver        = ver;
        p.level      = level;
        emit ProposalCreated(nextPid, msg.sender, softwareId, ver, level, PatchLevelDefenseType.AccessControl);
        nextPid++;
    }

    function approvePatch(uint256 pid) external {
        Proposal storage p = proposals[pid];
        require(!p.executed, "already executed");
        require(isApprover(msg.sender), "not approver");
        require(!p.voted[msg.sender], "already voted");
        p.voted[msg.sender] = true;
        p.approvals++;
        emit ProposalApproved(pid, msg.sender, p.approvals, PatchLevelDefenseType.AuditLogging);
        if (p.approvals >= threshold) {
            p.executed = true;
            // apply the patch (in real system, integrate with patch registry)
            emit PatchExecuted(pid, p.softwareId, p.ver, p.level, PatchLevelDefenseType.AuditLogging);
        }
    }
}
