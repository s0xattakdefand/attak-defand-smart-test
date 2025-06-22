// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title PatchSetSuite.sol
/// @notice On-chain analogues of “Patch Set” deployment patterns:
///   Types: Manual, Automated, Rolling, Bulk  
///   AttackTypes: IncompleteApplication, Rollback, Tampering, Bypass  
///   DefenseTypes: IntegrityVerification, TransactionalApply, RollbackProtection, AccessControl  

enum PatchSetType           { Manual, Automated, Rolling, Bulk }
enum PatchSetAttackType     { IncompleteApplication, Rollback, Tampering, Bypass }
enum PatchSetDefenseType    { IntegrityVerification, TransactionalApply, RollbackProtection, AccessControl }

error PST__InvalidSignature();
error PST__MismatchedLengths();
error PST__NotApprover();
error PST__AlreadyExecuted();
error PST__ThresholdNotMet();

//─────────────────────────────────────────────────────────────────────────────
// 1) VULNERABLE PATCHSET REGISTRY
//    • no checks: any caller may add or modify any patch → Tampering, Bypass
//─────────────────────────────────────────────────────────────────────────────
contract PatchSetVuln {
    // setId → patchName → version
    mapping(bytes32 => mapping(string => string)) public patches;
    event PatchRegistered(
        address indexed who,
        bytes32 indexed setId,
        string         name,
        string         version,
        PatchSetType   ptype,
        PatchSetAttackType attack
    );

    function registerPatch(bytes32 setId, PatchSetType ptype, string calldata name, string calldata version) external {
        patches[setId][name] = version;
        emit PatchRegistered(msg.sender, setId, name, version, ptype, PatchSetAttackType.Tampering);
    }
}

//─────────────────────────────────────────────────────────────────────────────
// 2) ATTACK STUB
//    • demonstrates tampering and incomplete application
//─────────────────────────────────────────────────────────────────────────────
contract Attack_PatchSet {
    PatchSetVuln public target;
    constructor(PatchSetVuln _t) { target = _t; }

    function tamper(bytes32 setId, string calldata name, string calldata fakeVersion) external {
        target.registerPatch(setId, PatchSetType.Manual, name, fakeVersion);
    }

    function partialApply(bytes32 setId, string[] calldata names, string[] calldata versions) external {
        // simulate incomplete by only applying half
        uint mid = names.length / 2;
        for (uint i = 0; i < mid; i++) {
            target.registerPatch(setId, PatchSetType.Bulk, names[i], versions[i]);
        }
    }
}

//─────────────────────────────────────────────────────────────────────────────
// 3) SAFE WITH INTEGRITY VERIFICATION
//    • Defense: IntegrityVerification – require authority signature per patch
//─────────────────────────────────────────────────────────────────────────────
contract PatchSetSafeIntegrity {
    address public authority;
    mapping(bytes32 => mapping(string => string)) public patches;
    event PatchRegistered(
        address indexed who,
        bytes32 indexed setId,
        string         name,
        string         version,
        PatchSetDefenseType defense
    );

    constructor(address _authority) {
        authority = _authority;
    }

    error PST__InvalidSignature();

    function registerPatch(
        bytes32 setId,
        string calldata name,
        string calldata version,
        bytes calldata sig
    ) external {
        // verify signature over (setId||name||version)
        bytes32 msgHash = keccak256(abi.encodePacked(setId, name, version));
        bytes32 ethMsg  = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8, bytes32, bytes32));
        if (ecrecover(ethMsg, v, r, s) != authority) revert PST__InvalidSignature();

        patches[setId][name] = version;
        emit PatchRegistered(msg.sender, setId, name, version, PatchSetDefenseType.IntegrityVerification);
    }
}

//─────────────────────────────────────────────────────────────────────────────
// 4) SAFE WITH TRANSACTIONAL APPLY
//    • Defense: TransactionalApply – atomic apply of whole set or revert
//─────────────────────────────────────────────────────────────────────────────
contract PatchSetSafeTransactional {
    mapping(bytes32 => mapping(string => string)) public patches;
    event PatchSetApplied(
        address indexed who,
        bytes32 indexed setId,
        PatchSetType   ptype,
        string[]       names,
        string[]       versions,
        PatchSetDefenseType defense
    );

    error PST__MismatchedLengths();

    function applyPatchSet(
        bytes32 setId,
        PatchSetType ptype,
        string[] calldata names,
        string[] calldata versions
    ) external {
        if (names.length != versions.length) revert PST__MismatchedLengths();
        // atomic: revert will undo all writes
        for (uint i = 0; i < names.length; i++) {
            patches[setId][names[i]] = versions[i];
        }
        emit PatchSetApplied(msg.sender, setId, ptype, names, versions, PatchSetDefenseType.TransactionalApply);
    }
}

//─────────────────────────────────────────────────────────────────────────────
// 5) SAFE ADVANCED WITH MULTI-SIG & ROLLBACK PROTECTION
//    • Defense: AccessControl + RollbackProtection – N-of-M approvals before apply
//─────────────────────────────────────────────────────────────────────────────
contract PatchSetSafeAdvanced {
    address[] public approvers;
    uint256 public threshold;

    struct Proposal {
        bytes32     setId;
        string[]    names;
        string[]    versions;
        uint256     approvals;
        bool        executed;
        mapping(address=>bool) voted;
    }
    mapping(uint256 => Proposal) public proposals;
    mapping(bytes32 => mapping(string => string)) public patches;
    uint256 public nextPid;

    event ProposalCreated(
        uint256 indexed pid,
        address indexed proposer,
        bytes32     setId,
        PatchSetDefenseType defense
    );
    event ProposalApproved(
        uint256 indexed pid,
        address indexed approver,
        uint256 approvals,
        PatchSetDefenseType defense
    );
    event PatchSetExecuted(
        uint256 indexed pid,
        address indexed executor,
        bytes32     setId,
        PatchSetDefenseType defense
    );

    error PST__NotApprover();
    error PST__AlreadyExecuted();
    error PST__ThresholdNotMet();

    constructor(address[] memory _approvers, uint256 _threshold) {
        require(_approvers.length >= _threshold, "threshold too high");
        approvers = _approvers;
        threshold = _threshold;
    }

    function isApprover(address who) internal view returns(bool) {
        for (uint i = 0; i < approvers.length; i++) {
            if (approvers[i] == who) return true;
        }
        return false;
    }

    function proposePatchSet(
        bytes32 setId,
        string[] calldata names,
        string[] calldata versions
    ) external {
        require(isApprover(msg.sender), "not approver");
        Proposal storage p = proposals[nextPid];
        p.setId = setId;
        p.names = names;
        p.versions = versions;
        emit ProposalCreated(nextPid, msg.sender, setId, PatchSetDefenseType.AccessControl);
        nextPid++;
    }

    function approvePatchSet(uint256 pid) external {
        Proposal storage p = proposals[pid];
        require(!p.executed, "already executed");
        require(isApprover(msg.sender), "not approver");
        require(!p.voted[msg.sender], "already voted");
        p.voted[msg.sender] = true;
        p.approvals++;
        emit ProposalApproved(pid, msg.sender, p.approvals, PatchSetDefenseType.RollbackProtection);
        if (p.approvals >= threshold) {
            // execute: atomic apply
            for (uint i = 0; i < p.names.length; i++) {
                patches[p.setId][p.names[i]] = p.versions[i];
            }
            p.executed = true;
            emit PatchSetExecuted(pid, msg.sender, p.setId, PatchSetDefenseType.RollbackProtection);
        }
    }
}
