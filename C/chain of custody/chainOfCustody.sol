// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title ChainOfCustodySuite.sol
/// @notice On-chain analogues of “Chain of Custody” evidence management patterns:
///   Types: Physical, Digital, Hybrid  
///   AttackTypes: Alteration, Loss, UnauthorizedAccess  
///   DefenseTypes: Logging, TamperEvidence, MultiSig, TimeStamping  

enum ChainOfCustodyType         { Physical, Digital, Hybrid }
enum ChainOfCustodyAttackType   { Alteration, Loss, UnauthorizedAccess }
enum ChainOfCustodyDefenseType  { Logging, TamperEvidence, MultiSig, TimeStamping }

error COC__NotOwner();
error COC__Tampered();
error COC__Unauthorized();
error COC__AlreadyProcessed();
error COC__InsufficientApprovals();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE CUSTODY (no logging, no protection)
//    • Attack: Alteration, Loss
////////////////////////////////////////////////////////////////////////////////
contract ChainOfCustodyVuln {
    mapping(uint256 => address) public custodian;
    event EvidenceTransferred(
        uint256 indexed id,
        address indexed from,
        address indexed to,
        ChainOfCustodyType ctype,
        ChainOfCustodyAttackType attack
    );

    function transfer(uint256 id, address to, ChainOfCustodyType ctype) external {
        // ❌ no check or log: unauthorized or lost evidence
        custodian[id] = to;
        emit EvidenceTransferred(id, msg.sender, to, ctype, ChainOfCustodyAttackType.UnauthorizedAccess);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • demonstrates unauthorized transfer and deletion
////////////////////////////////////////////////////////////////////////////////
contract Attack_ChainOfCustody {
    ChainOfCustodyVuln public target;
    constructor(ChainOfCustodyVuln _t) { target = _t; }

    function hijackTransfer(uint256 id, address to, ChainOfCustodyType ctype) external {
        target.transfer(id, to, ctype);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH LOGGING
//    • Defense: Logging – append-only transfer records
////////////////////////////////////////////////////////////////////////////////
contract ChainOfCustodySafeLogging {
    mapping(uint256 => address) public custodian;
    struct Record { uint256 timestamp; address from; address to; ChainOfCustodyType ctype; }
    mapping(uint256 => Record[]) public history;
    event EvidenceTransferred(
        uint256 indexed id,
        address indexed from,
        address indexed to,
        ChainOfCustodyType ctype,
        ChainOfCustodyDefenseType defense
    );

    function transfer(uint256 id, address to, ChainOfCustodyType ctype) external {
        address from = custodian[id];
        // record in history
        history[id].push(Record(block.timestamp, from, to, ctype));
        custodian[id] = to;
        emit EvidenceTransferred(id, from, to, ctype, ChainOfCustodyDefenseType.Logging);
    }

    function getHistory(uint256 id) external view returns (Record[] memory) {
        return history[id];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH TAMPER EVIDENCE
//    • Defense: TamperEvidence – hash-chain logs for integrity
////////////////////////////////////////////////////////////////////////////////
contract ChainOfCustodySafeTamper {
    mapping(uint256 => address) public custodian;
    struct Entry { bytes32 prevHash; uint256 timestamp; address from; address to; ChainOfCustodyType ctype; }
    mapping(uint256 => Entry[]) public ledger;
    event EvidenceTransferred(
        uint256 indexed id,
        address indexed from,
        address indexed to,
        ChainOfCustodyType ctype,
        ChainOfCustodyDefenseType defense
    );
    error COC__Tampered();

    function transfer(uint256 id, address to, ChainOfCustodyType ctype) external {
        address from = custodian[id];
        // compute new hash linking to previous entry
        bytes32 prev = ledger[id].length == 0 ? bytes32(0) : keccak256(abi.encodePacked(ledger[id][ledger[id].length-1]));
        Entry memory e = Entry(prev, block.timestamp, from, to, ctype);
        ledger[id].push(e);
        custodian[id] = to;
        emit EvidenceTransferred(id, from, to, ctype, ChainOfCustodyDefenseType.TamperEvidence);
    }

    function verify(uint256 id) external view {
        bytes32 hash = bytes32(0);
        for (uint i = 0; i < ledger[id].length; i++) {
            Entry storage e = ledger[id][i];
            hash = keccak256(abi.encodePacked(hash, e.timestamp, e.from, e.to, e.ctype));
            require(hash == keccak256(abi.encodePacked(e)), "tamper detected");
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH MULTISIG & TIMESTAMPING
//    • Defense: MultiSig – require N-of-M approvals  
//               TimeStamping – record standardized timestamp
////////////////////////////////////////////////////////////////////////////////
contract ChainOfCustodySafeAdvanced {
    mapping(uint256 => address) public custodian;
    address[] public approvers;
    uint256 public threshold;

    struct Pending { address to; ChainOfCustodyType ctype; uint256 approvals; mapping(address=>bool) approved; bool executed; }
    mapping(uint256 => Pending) public pendings;

    event TransferProposed(
        uint256 indexed id,
        address indexed proposer,
        address to,
        ChainOfCustodyType ctype,
        ChainOfCustodyDefenseType defense
    );
    event TransferApproved(
        uint256 indexed id,
        address indexed approver,
        uint256 approvals,
        ChainOfCustodyDefenseType defense
    );
    event TransferExecuted(
        uint256 indexed id,
        address indexed from,
        address indexed to,
        ChainOfCustodyType ctype,
        uint256 timestamp,
        ChainOfCustodyDefenseType defense
    );
    error COC__Unauthorized();
    error COC__InsufficientApprovals();

    constructor(address[] memory _approvers, uint256 _threshold) {
        require(_approvers.length >= _threshold, "threshold too high");
        approvers = _approvers;
        threshold = _threshold;
    }

    function proposeTransfer(uint256 id, address to, ChainOfCustodyType ctype) external {
        bool isApprover;
        for (uint i; i < approvers.length; i++) {
            if (approvers[i] == msg.sender) { isApprover = true; break; }
        }
        if (!isApprover) revert COC__Unauthorized();
        Pending storage p = pendings[id];
        require(!p.executed, "already executed");
        p.to = to;
        p.ctype = ctype;
        emit TransferProposed(id, msg.sender, to, ctype, ChainOfCustodyDefenseType.MultiSig);
    }

    function approveTransfer(uint256 id) external {
        Pending storage p = pendings[id];
        require(!p.executed, "already executed");
        bool isApprover;
        for (uint i; i < approvers.length; i++) {
            if (approvers[i] == msg.sender) { isApprover = true; break; }
        }
        if (!isApprover) revert COC__Unauthorized();
        if (!p.approved[msg.sender]) {
            p.approved[msg.sender] = true;
            p.approvals++;
            emit TransferApproved(id, msg.sender, p.approvals, ChainOfCustodyDefenseType.MultiSig);
        }
        if (p.approvals >= threshold) {
            p.executed = true;
            address from = custodian[id];
            custodian[id] = p.to;
            emit TransferExecuted(id, from, p.to, p.ctype, block.timestamp, ChainOfCustodyDefenseType.TimeStamping);
        }
    }
}
