// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title GovernanceAndConsensusAnalysisSuite.sol
/// @notice On‐chain analogues of “Governance and Consensus Analysis” patterns:
///   Types: OnChainVoting, OffChainVoting, DelegatedVoting, HybridConsensus  
///   AttackTypes: VoteBuying, SybilAttack, Censorship, ForkAttack  
///   DefenseTypes: AccessControl, QuorumCheck, RateLimit, SignatureValidation, AuditLogging

enum GovConsType          { OnChainVoting, OffChainVoting, DelegatedVoting, HybridConsensus }
enum GovConsAttackType    { VoteBuying, SybilAttack, Censorship, ForkAttack }
enum GovConsDefenseType   { AccessControl, QuorumCheck, RateLimit, SignatureValidation, AuditLogging }

error GCA__NotAuthorized();
error GCA__AlreadyVoted();
error GCA__TooManyRequests();
error GCA__InvalidSignature();
error GCA__QuorumNotReached();

struct Proposal {
    uint256    id;
    string     description;
    uint256    yes;
    uint256    no;
    bool       executed;
}

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE GOVERNANCE
//    • ❌ no checks: anyone may propose or vote multiple times → SybilAttack
////////////////////////////////////////////////////////////////////////////////
contract GCAvuln {
    mapping(uint256 => Proposal) public proposals;
    mapping(uint256 => mapping(address => bool)) public hasVoted;
    uint256 public nextId;

    event ProposalCreated(
        address indexed who,
        uint256           proposalId,
        GovConsType       gtype,
        GovConsAttackType attack
    );
    event Voted(
        address indexed who,
        uint256           proposalId,
        bool              support,
        GovConsType       gtype,
        GovConsAttackType attack
    );

    function propose(string calldata desc, GovConsType gtype) external {
        proposals[nextId] = Proposal(nextId, desc, 0, 0, false);
        emit ProposalCreated(msg.sender, nextId, gtype, GovConsAttackType.Censorship);
        nextId++;
    }

    function vote(uint256 pid, bool support, GovConsType gtype) external {
        // no check for duplicate voting
        if (support) proposals[pid].yes++;
        else           proposals[pid].no++;
        emit Voted(msg.sender, pid, support, gtype, GovConsAttackType.SybilAttack);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates vote buying, sybil, censorship, fork
////////////////////////////////////////////////////////////////////////////////
contract Attack_GCA {
    GCAvuln public target;
    uint256 public lastPid;

    constructor(GCAvuln _t) { target = _t; }

    function buyVotes(uint256 pid, address[] calldata voters) external {
        // attacker directs votes
        for (uint i = 0; i < voters.length; i++) {
            // in a real scenario would use delegatecall or compromise keys
            target.vote(pid, true, GovConsType.OnChainVoting);
        }
        lastPid = pid;
    }

    function sybil(uint256 pid, uint count) external {
        // simulate many identities
        for (uint i = 0; i < count; i++) {
            target.vote(pid, false, GovConsType.OnChainVoting);
        }
    }

    function censor(uint256 pid) external {
        // simulate censorship by not calling vote at all
        lastPid = pid;
    }

    function replayVote() external {
        target.vote(lastPid, true, GovConsType.OnChainVoting);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may propose or vote
////////////////////////////////////////////////////////////////////////////////
contract GCASafeAccess {
    mapping(uint256 => Proposal) public proposals;
    mapping(uint256 => mapping(address => bool)) public hasVoted;
    uint256 public nextId;
    address public owner;

    event ProposalCreated(
        address indexed who,
        uint256           proposalId,
        GovConsType       gtype,
        GovConsDefenseType defense
    );
    event Voted(
        address indexed who,
        uint256           proposalId,
        bool              support,
        GovConsType       gtype,
        GovConsDefenseType defense
    );

    constructor() {
        owner = msg.sender;
    }
    modifier onlyOwner() {
        if (msg.sender != owner) revert GCA__NotAuthorized();
        _;
    }

    function propose(string calldata desc, GovConsType gtype) external onlyOwner {
        proposals[nextId] = Proposal(nextId, desc, 0, 0, false);
        emit ProposalCreated(msg.sender, nextId, gtype, GovConsDefenseType.AccessControl);
        nextId++;
    }

    function vote(uint256 pid, bool support, GovConsType gtype) external onlyOwner {
        if (hasVoted[pid][msg.sender]) revert GCA__AlreadyVoted();
        hasVoted[pid][msg.sender] = true;
        if (support) proposals[pid].yes++;
        else           proposals[pid].no++;
        emit Voted(msg.sender, pid, support, gtype, GovConsDefenseType.AccessControl);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH QUORUM CHECK & RATE LIMIT
//    • ✅ Defense: QuorumCheck – require min votes before execute  
//               RateLimit   – cap proposals/votes per block
////////////////////////////////////////////////////////////////////////////////
contract GCASafeValidate {
    mapping(uint256 => Proposal) public proposals;
    mapping(uint256 => mapping(address => bool)) public hasVoted;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public nextId;
    uint256 public constant QUORUM = 3;
    uint256 public constant MAX_CALLS = 5;

    event ProposalCreated(
        address indexed who,
        uint256           proposalId,
        GovConsType       gtype,
        GovConsDefenseType defense
    );
    event Voted(
        address indexed who,
        uint256           proposalId,
        bool              support,
        GovConsType       gtype,
        GovConsDefenseType defense
    );
    event Executed(
        address indexed who,
        uint256           proposalId,
        GovConsDefenseType defense
    );

    error GCA__TooManyRequests();
    error GCA__QuorumNotReached();

    function _rateLimit() internal {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert GCA__TooManyRequests();
    }

    function propose(string calldata desc, GovConsType gtype) external {
        _rateLimit();
        proposals[nextId] = Proposal(nextId, desc, 0, 0, false);
        emit ProposalCreated(msg.sender, nextId, gtype, GovConsDefenseType.RateLimit);
        nextId++;
    }

    function vote(uint256 pid, bool support, GovConsType gtype) external {
        _rateLimit();
        if (hasVoted[pid][msg.sender]) revert GCA__AlreadyVoted();
        hasVoted[pid][msg.sender] = true;
        if (support) proposals[pid].yes++;
        else           proposals[pid].no++;
        emit Voted(msg.sender, pid, support, gtype, GovConsDefenseType.RateLimit);
    }

    function execute(uint256 pid) external {
        Proposal storage p = proposals[pid];
        require(!p.executed, "already executed");
        if (p.yes + p.no < QUORUM) revert GCA__QuorumNotReached();
        p.executed = true;
        emit Executed(msg.sender, pid, GovConsDefenseType.QuorumCheck);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & AUDIT LOGGING
//    • ✅ Defense: SignatureValidation – require admin‐signed proposals/votes  
//               AuditLogging       – record all changes
////////////////////////////////////////////////////////////////////////////////
contract GCASafeAdvanced {
    mapping(uint256 => Proposal) public proposals;
    mapping(uint256 => mapping(address => bool)) public hasVoted;
    uint256 public nextId;
    address public signer;

    event ProposalCreated(
        address indexed who,
        uint256           proposalId,
        GovConsType       gtype,
        GovConsDefenseType defense
    );
    event Voted(
        address indexed who,
        uint256           proposalId,
        bool              support,
        GovConsType       gtype,
        GovConsDefenseType defense
    );
    event AuditLog(
        address indexed who,
        string            action,
        uint256           proposalId,
        GovConsDefenseType defense
    );

    error GCA__InvalidSignature();
    error GCA__AlreadyVoted();

    constructor(address _signer) {
        signer = _signer;
    }

    function propose(
        string calldata desc,
        GovConsType gtype,
        bytes calldata sig
    ) external {
        // verify signature over (desc||gtype)
        bytes32 h = keccak256(abi.encodePacked(desc, gtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert GCA__InvalidSignature();

        proposals[nextId] = Proposal(nextId, desc, 0, 0, false);
        emit ProposalCreated(msg.sender, nextId, gtype, GovConsDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "propose", nextId, GovConsDefenseType.AuditLogging);
        nextId++;
    }

    function vote(
        uint256 pid,
        bool support,
        GovConsType gtype,
        bytes calldata sig
    ) external {
        if (hasVoted[pid][msg.sender]) revert GCA__AlreadyVoted();
        // verify signature over (pid||support)
        bytes32 h = keccak256(abi.encodePacked(pid, support));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert GCA__InvalidSignature();

        hasVoted[pid][msg.sender] = true;
        if (support) proposals[pid].yes++;
        else           proposals[pid].no++;
        emit Voted(msg.sender, pid, support, gtype, GovConsDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "vote", pid, GovConsDefenseType.AuditLogging);
    }
}
