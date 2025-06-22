// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AuditingSuite.sol
/// @notice On‑chain analogues of “Auditing” patterns:
///   Types: InternalAudit, ExternalAudit, RealTimeMonitor, Forensic  
///   AttackTypes: LogTampering, Omission, Flooding, Replay  
///   DefenseTypes: ImmutableLogs, Alerting, RateLimit, MultiSig  

enum AuditingType            { InternalAudit, ExternalAudit, RealTimeMonitor, Forensic }
enum AuditingAttackType      { LogTampering, Omission, Flooding, Replay }
enum AuditingDefenseType     { ImmutableLogs, Alerting, RateLimit, MultiSig }

error AUD__NotAuthorized();
error AUD__TooMany();
error AUD__AlreadySubmitted();
error AUD__InvalidEntry();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE AUDITOR
//
//    • ❌ logs overwritten in storage, no append‑only guarantee  
//    • Attack: Omission, LogTampering
////////////////////////////////////////////////////////////////////////////////
contract AuditingVuln {
    mapping(uint256 => string) public entries;  // id → log entry
    event AuditLogged(
        uint256 indexed id,
        AuditingType     atype,
        string           entry,
        AuditingAttackType attack
    );

    function log(uint256 id, AuditingType atype, string calldata entry) external {
        entries[id] = entry;
        emit AuditLogged(id, atype, entry, AuditingAttackType.LogTampering);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//
//    • deletes or overwrites logs, floods entries
////////////////////////////////////////////////////////////////////////////////
contract Attack_Auditing {
    AuditingVuln public target;
    constructor(AuditingVuln _t) { target = _t; }

    function tamper(uint256 id, string calldata fake) external {
        target.log(id, AuditingType.InternalAudit, fake);
    }

    function flood(uint256 startId, uint count, string calldata spam) external {
        for (uint i = 0; i < count; i++) {
            target.log(startId + i, AuditingType.RealTimeMonitor, spam);
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE BASIC AUDIT (IMMUTABLE LOGS)
//    • Defense: ImmutableLogs – append‑only, cannot overwrite
////////////////////////////////////////////////////////////////////////////////
contract AuditingSafeImmutable {
    struct Entry { uint256 id; AuditingType atype; string entry; }
    mapping(uint256 => Entry[]) public logbook;
    address public owner;
    event AuditLogged(
        uint256 indexed id,
        AuditingType     atype,
        string           entry,
        AuditingDefenseType defense
    );

    constructor() { owner = msg.sender; }

    function log(uint256 id, AuditingType atype, string calldata entry) external {
        require(msg.sender == owner, "not authorized");
        logbook[id].push(Entry(id, atype, entry));
        emit AuditLogged(id, atype, entry, AuditingDefenseType.ImmutableLogs);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE AUDIT WITH RATE‑LIMIT & ALERTING
//    • Defense: RateLimit – cap logs per block  
//               Alerting – emit alert on threshold breach
////////////////////////////////////////////////////////////////////////////////
contract AuditingSafeAlert {
    struct Entry { uint256 blockNum; string entry; }
    mapping(uint256 => Entry[]) public logbook;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public countInBlock;
    uint256 public constant MAX_PER_BLOCK = 5;
    address public owner;

    event AuditLogged(
        uint256 indexed id,
        AuditingType     atype,
        string           entry,
        AuditingDefenseType defense
    );
    event AuditAlert(
        address indexed who,
        uint256 indexed id,
        string           reason,
        AuditingDefenseType defense
    );

    constructor() { owner = msg.sender; }

    error AUD__TooMany();

    function log(uint256 id, AuditingType atype, string calldata entry) external {
        require(msg.sender == owner, "not authorized");

        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender]++;
        if (countInBlock[msg.sender] > MAX_PER_BLOCK) {
            emit AuditAlert(msg.sender, id, "rate limit exceeded", AuditingDefenseType.RateLimit);
            revert AUD__TooMany();
        }

        logbook[id].push(Entry(block.number, entry));
        emit AuditLogged(id, atype, entry, AuditingDefenseType.Alerting);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE MULTI‑SIG AUDIT (FOR FORENSIC)
//    • Defense: MultiSig – require N-of-M approvers for critical logs
////////////////////////////////////////////////////////////////////////////////
contract AuditingSafeMultiSig {
    struct Pending { uint256 id; AuditingType atype; string entry; uint approvals; mapping(address=>bool) approved; bool executed; }
    mapping(uint256 => Pending) public pendings;
    address[] public approvers;
    uint256 public threshold;
    event AuditProposed(
        uint256 indexed pid,
        uint256 indexed id,
        AuditingType     atype,
        string           entry
    );
    event AuditApproved(
        uint256 indexed pid,
        address indexed approver,
        AuditingDefenseType defense
    );
    event AuditExecuted(
        uint256 indexed pid,
        uint256 indexed id,
        AuditingDefenseType defense
    );

    constructor(address[] memory _approvers, uint256 _threshold) {
        require(_approvers.length >= _threshold, "threshold too high");
        approvers = _approvers;
        threshold = _threshold;
    }

    function propose(uint256 pid, uint256 id, AuditingType atype, string calldata entry) external {
        // anyone may propose
        Pending storage p = pendings[pid];
        require(!p.executed, "already executed");
        p.id = id; p.atype = atype; p.entry = entry;
        emit AuditProposed(pid, id, atype, entry);
    }

    function approve(uint256 pid) external {
        Pending storage p = pendings[pid];
        require(!p.executed, "already executed");
        bool isApprover;
        for (uint i; i < approvers.length; i++) {
            if (approvers[i] == msg.sender) { isApprover = true; break; }
        }
        require(isApprover, "not approver");
        require(!p.approved[msg.sender], "already approved");
        p.approved[msg.sender] = true;
        p.approvals++;
        emit AuditApproved(pid, msg.sender, AuditingDefenseType.MultiSig);
        if (p.approvals >= threshold) {
            p.executed = true;
            emit AuditExecuted(pid, p.id, AuditingDefenseType.MultiSig);
        }
    }
}
