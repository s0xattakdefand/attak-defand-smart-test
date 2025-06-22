// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title PayloadControlCenterSuite.sol
/// @notice On-chain analogues of “Payload Control Center” patterns:
///   Types: RemoteExec, Telemetry, Sync, Batch  
///   AttackTypes: UnauthorizedPayload, Tampering, Replay, Injection  
///   DefenseTypes: Auth, IntegrityCheck, RateLimit, AuditLogging  

enum PayloadControlCenterType        { RemoteExec, Telemetry, Sync, Batch }
enum PayloadControlCenterAttackType  { UnauthorizedPayload, Tampering, Replay, Injection }
enum PayloadControlCenterDefenseType { Auth, IntegrityCheck, RateLimit, AuditLogging }

error PCC__NotAuthorized();
error PCC__InvalidSignature();
error PCC__TooManyRequests();
error PCC__NotOwner();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE CENTER
//    • no checks: any caller may send or schedule payload → Tampering
////////////////////////////////////////////////////////////////////////////////
contract PCCVuln {
    event PayloadSent(
        address indexed who,
        PayloadControlCenterType  ptype,
        bytes                     payload,
        PayloadControlCenterAttackType attack
    );

    function sendPayload(PayloadControlCenterType ptype, bytes calldata payload) external {
        // ❌ no authorization or integrity: attacker can tamper
        emit PayloadSent(msg.sender, ptype, payload, PayloadControlCenterAttackType.Tampering);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • demonstrates unauthorized send and replay
////////////////////////////////////////////////////////////////////////////////
contract Attack_PCC {
    PCCVuln public target;
    bytes public lastPayload;
    PayloadControlCenterType public lastType;

    constructor(PCCVuln _t) { target = _t; }

    function capture(PayloadControlCenterType ptype, bytes calldata payload) external {
        lastType = ptype;
        lastPayload = payload;
    }

    function unauthorizedSend(bytes calldata payload) external {
        target.sendPayload(PayloadControlCenterType.RemoteExec, payload);
    }

    function replay() external {
        target.sendPayload(lastType, lastPayload);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH AUTHENTICATION
//    • Defense: Auth – only owner may send payload
////////////////////////////////////////////////////////////////////////////////
contract PCCSafeAuth {
    address public owner;
    event PayloadSent(
        address indexed who,
        PayloadControlCenterType  ptype,
        bytes                     payload,
        PayloadControlCenterDefenseType defense
    );

    constructor() {
        owner = msg.sender;
    }

    function sendPayload(PayloadControlCenterType ptype, bytes calldata payload) external {
        if (msg.sender != owner) revert PCC__NotAuthorized();
        emit PayloadSent(msg.sender, ptype, payload, PayloadControlCenterDefenseType.Auth);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH INTEGRITY CHECK & RATE-LIMITING
//    • Defense: IntegrityCheck – require signed payload  
//               RateLimit – cap sends per block
////////////////////////////////////////////////////////////////////////////////
contract PCCSafeIntegrityRate {
    address public signer;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public sendsInBlock;
    uint256 public constant MAX_SENDS = 5;

    event PayloadSent(
        address indexed who,
        PayloadControlCenterType  ptype,
        bytes                     payload,
        PayloadControlCenterDefenseType defense
    );

    error PCC__InvalidSignature();
    error PCC__TooManyRequests();

    constructor(address _signer) {
        signer = _signer;
    }

    function sendPayload(
        PayloadControlCenterType ptype,
        bytes calldata payload,
        bytes calldata sig
    ) external {
        // rate-limit per sender
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            sendsInBlock[msg.sender] = 0;
        }
        sendsInBlock[msg.sender]++;
        if (sendsInBlock[msg.sender] > MAX_SENDS) revert PCC__TooManyRequests();

        // integrity: verify signature over (sender||ptype||payload)
        bytes32 msgHash = keccak256(abi.encodePacked(msg.sender, ptype, payload));
        bytes32 ethMsg  = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8, bytes32, bytes32));
        if (ecrecover(ethMsg, v, r, s) != signer) revert PCC__InvalidSignature();

        emit PayloadSent(msg.sender, ptype, payload, PayloadControlCenterDefenseType.IntegrityCheck);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH AUDIT LOGGING & MULTI-SIG
//    • Defense: AuditLogging – log every send  
//               Auth (Multi-sig) – require N-of-M approvals
////////////////////////////////////////////////////////////////////////////////
contract PCCSafeAdvanced {
    address[] public approvers;
    uint256 public threshold;

    struct Proposal {
        PayloadControlCenterType ptype;
        bytes payload;
        uint256 approvals;
        bool executed;
        mapping(address => bool) voted;
    }
    mapping(uint256 => Proposal) public proposals;
    uint256 public nextPid;

    event ProposalCreated(
        uint256 indexed pid,
        address indexed proposer,
        PayloadControlCenterType ptype,
        PayloadControlCenterDefenseType defense
    );
    event ProposalApproved(
        uint256 indexed pid,
        address indexed approver,
        uint256 approvals,
        PayloadControlCenterDefenseType defense
    );
    event PayloadSent(
        uint256 indexed pid,
        address indexed executor,
        PayloadControlCenterType ptype,
        bytes payload,
        PayloadControlCenterDefenseType defense
    );

    error PCC__NotApprover();
    error PCC__AlreadyExecuted();
    error PCC__ThresholdNotMet();

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

    function proposePayload(PayloadControlCenterType ptype, bytes calldata payload) external {
        if (!isApprover(msg.sender)) revert PCC__NotApprover();
        Proposal storage p = proposals[nextPid];
        p.ptype = ptype;
        p.payload = payload;
        emit ProposalCreated(nextPid, msg.sender, ptype, PayloadControlCenterDefenseType.AccessControl);
        nextPid++;
    }

    function approvePayload(uint256 pid) external {
        Proposal storage p = proposals[pid];
        if (p.executed) revert PCC__AlreadyExecuted();
        if (!isApprover(msg.sender)) revert PCC__NotApprover();
        if (!p.voted[msg.sender]) {
            p.voted[msg.sender] = true;
            p.approvals++;
            emit ProposalApproved(pid, msg.sender, p.approvals, PayloadControlCenterDefenseType.AuditLogging);
        }
        if (p.approvals >= threshold) {
            p.executed = true;
            emit PayloadSent(pid, msg.sender, p.ptype, p.payload, PayloadControlCenterDefenseType.AuditLogging);
        }
    }
}
