// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title CandidateForDeletionSuite.sol
/// @notice On‐chain analogues of “Candidate for Deletion” workflows:
///   Types: ObsoleteRecord, StaleSession, ExpiredToken, DeprecatedContract  
///   AttackTypes: UnauthorizedDeletion, DataLoss, ReplayRestore, DenialOfService  
///   DefenseTypes: SoftDelete, AccessControl, Confirmation, AuditLogging, RateLimit

enum CandidateDeletionType         { ObsoleteRecord, StaleSession, ExpiredToken, DeprecatedContract }
enum CandidateDeletionAttackType   { UnauthorizedDeletion, DataLoss, ReplayRestore, DenialOfService }
enum CandidateDeletionDefenseType  { SoftDelete, AccessControl, Confirmation, AuditLogging, RateLimit }

error CFD__NotAuthorized();
error CFD__AlreadyDeleted();
error CFD__NotMarked();
error CFD__TooManyRequests();
error CFD__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE MANAGER
//    • ❌ no checks: anyone may delete immediately → DataLoss
////////////////////////////////////////////////////////////////////////////////
contract CandidateForDeletionVuln {
    mapping(bytes32 => string) public items;
    mapping(bytes32 => bool)   public deleted;

    event Deleted(
        address indexed who,
        bytes32           itemId,
        CandidateDeletionType dtype,
        CandidateDeletionAttackType attack
    );

    function addItem(bytes32 itemId, string calldata data) external {
        items[itemId] = data;
    }

    function deleteItem(bytes32 itemId, CandidateDeletionType dtype) external {
        delete items[itemId];
        deleted[itemId] = true;
        emit Deleted(msg.sender, itemId, dtype, CandidateDeletionAttackType.DataLoss);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates unauthorized deletion & replay
////////////////////////////////////////////////////////////////////////////////
contract Attack_CandidateForDeletion {
    CandidateForDeletionVuln public target;
    bytes32 public lastId;

    constructor(CandidateForDeletionVuln _t) { target = _t; }

    function unauthorizedDelete(bytes32 itemId) external {
        target.deleteItem(itemId, CandidateDeletionType.ObsoleteRecord);
        lastId = itemId;
    }

    function replayDelete() external {
        target.deleteItem(lastId, CandidateDeletionType.ObsoleteRecord);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may delete
////////////////////////////////////////////////////////////////////////////////
contract CandidateForDeletionSafeAccess {
    mapping(bytes32 => string) public items;
    mapping(bytes32 => bool)   public deleted;
    address public owner;

    event Deleted(
        address indexed who,
        bytes32           itemId,
        CandidateDeletionType dtype,
        CandidateDeletionDefenseType defense
    );

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert CFD__NotAuthorized();
        _;
    }

    function addItem(bytes32 itemId, string calldata data) external {
        items[itemId] = data;
    }

    function deleteItem(bytes32 itemId, CandidateDeletionType dtype) external onlyOwner {
        if (deleted[itemId]) revert CFD__AlreadyDeleted();
        delete items[itemId];
        deleted[itemId] = true;
        emit Deleted(msg.sender, itemId, dtype, CandidateDeletionDefenseType.AccessControl);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH CONFIRMATION & RATE LIMIT
//    • ✅ Defense: Confirmation – two‐step delete  
//               RateLimit    – cap delete requests per block
////////////////////////////////////////////////////////////////////////////////
contract CandidateForDeletionSafeConfirm {
    mapping(bytes32 => string) public items;
    mapping(bytes32 => bool)   public marked;
    mapping(bytes32 => bool)   public deleted;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MAX_CALLS = 3;

    event MarkedForDeletion(
        address indexed who,
        bytes32           itemId,
        CandidateDeletionType dtype,
        CandidateDeletionDefenseType defense
    );
    event Deleted(
        address indexed who,
        bytes32           itemId,
        CandidateDeletionType dtype,
        CandidateDeletionDefenseType defense
    );

    error CFD__TooManyRequests();

    function addItem(bytes32 itemId, string calldata data) external {
        items[itemId] = data;
    }

    function markForDeletion(bytes32 itemId, CandidateDeletionType dtype) external {
        // rate-limit marking
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert CFD__TooManyRequests();

        require(bytes(items[itemId]).length != 0, "no such item");
        marked[itemId] = true;
        emit MarkedForDeletion(msg.sender, itemId, dtype, CandidateDeletionDefenseType.Confirmation);
    }

    function confirmDeletion(bytes32 itemId, CandidateDeletionType dtype) external {
        if (!marked[itemId]) revert CFD__NotMarked();
        delete items[itemId];
        deleted[itemId] = true;
        emit Deleted(msg.sender, itemId, dtype, CandidateDeletionDefenseType.Confirmation);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & AUDIT LOGGING
//    • ✅ Defense: SignatureValidation – require admin signature  
//               AuditLogging      – record every deletion
////////////////////////////////////////////////////////////////////////////////
contract CandidateForDeletionSafeAdvanced {
    mapping(bytes32 => string) public items;
    mapping(bytes32 => bool)   public deleted;
    address public signer;

    event AuditLog(
        address indexed who,
        bytes32           itemId,
        CandidateDeletionType dtype,
        CandidateDeletionDefenseType defense
    );

    error CFD__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function addItem(bytes32 itemId, string calldata data) external {
        items[itemId] = data;
    }

    function deleteItem(
        bytes32 itemId,
        CandidateDeletionType dtype,
        bytes calldata sig
    ) external {
        require(bytes(items[itemId]).length != 0, "no such item");
        // verify signature over (itemId||dtype)
        bytes32 h = keccak256(abi.encodePacked(itemId, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert CFD__InvalidSignature();

        delete items[itemId];
        deleted[itemId] = true;
        emit AuditLog(msg.sender, itemId, dtype, CandidateDeletionDefenseType.AuditLogging);
    }
}
