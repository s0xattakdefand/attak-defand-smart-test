// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title CandidateChecklistSuite.sol
/// @notice On‐chain analogues of “Candidate Checklist” workflows:
///   Types: PreScreen, Interview, BackgroundCheck, Offer  
///   AttackTypes: SpoofingCredentials, InterviewBias, DataTampering, OfferRescinded  
///   DefenseTypes: AccessControl, Validation, AuditLogging, RateLimit

enum CandidateChecklistType        { PreScreen, Interview, BackgroundCheck, Offer }
enum CandidateChecklistAttackType  { SpoofingCredentials, InterviewBias, DataTampering, OfferRescinded }
enum CandidateChecklistDefenseType { AccessControl, Validation, AuditLogging, RateLimit }

error CCL__NotOwner();
error CCL__InvalidItem();
error CCL__TooManyRequests();
error CCL__InvalidSignature();

struct Checklist {
    string[] items;
    bool     completed;
}

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE CHECKLIST MANAGER
//    • ❌ no controls: anyone may add/remove items or complete → DataTampering
////////////////////////////////////////////////////////////////////////////////
contract CandidateChecklistVuln {
    mapping(uint256 => Checklist) public checklists;

    event ItemAdded(
        uint256 indexed listId,
        string            item,
        CandidateChecklistType ctype,
        CandidateChecklistAttackType attack
    );
    event Completed(
        uint256 indexed listId,
        CandidateChecklistType ctype,
        CandidateChecklistAttackType attack
    );

    function addItem(uint256 listId, string calldata item, CandidateChecklistType ctype) external {
        checklists[listId].items.push(item);
        emit ItemAdded(listId, item, ctype, CandidateChecklistAttackType.DataTampering);
    }

    function completeList(uint256 listId, CandidateChecklistType ctype) external {
        checklists[listId].completed = true;
        emit Completed(listId, ctype, CandidateChecklistAttackType.OfferRescinded);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates tampering, spoofed entries, replay
////////////////////////////////////////////////////////////////////////////////
contract Attack_CandidateChecklist {
    CandidateChecklistVuln public target;
    uint256 public lastList;
    string  public lastItem;
    CandidateChecklistType public lastType;

    constructor(CandidateChecklistVuln _t) {
        target = _t;
    }

    function spoofItem(uint256 listId, string calldata item) external {
        target.addItem(listId, item, CandidateChecklistType.PreScreen);
        lastList = listId;
        lastItem = item;
        lastType = CandidateChecklistType.PreScreen;
    }

    function replayAdd() external {
        target.addItem(lastList, lastItem, lastType);
    }

    function forceComplete(uint256 listId) external {
        target.completeList(listId, CandidateChecklistType.Offer);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may modify
////////////////////////////////////////////////////////////////////////////////
contract CandidateChecklistSafeAccess {
    mapping(uint256 => Checklist) public checklists;
    address public owner;

    event ItemAdded(
        uint256 indexed listId,
        string            item,
        CandidateChecklistType ctype,
        CandidateChecklistDefenseType defense
    );
    event Completed(
        uint256 indexed listId,
        CandidateChecklistType ctype,
        CandidateChecklistDefenseType defense
    );

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert CCL__NotOwner();
        _;
    }

    function addItem(uint256 listId, string calldata item, CandidateChecklistType ctype) external onlyOwner {
        checklists[listId].items.push(item);
        emit ItemAdded(listId, item, ctype, CandidateChecklistDefenseType.AccessControl);
    }

    function completeList(uint256 listId, CandidateChecklistType ctype) external onlyOwner {
        checklists[listId].completed = true;
        emit Completed(listId, ctype, CandidateChecklistDefenseType.AccessControl);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH VALIDATION & RATE LIMIT
//    • ✅ Defense: Validation – nonempty items  
//               RateLimit – cap adds per block
////////////////////////////////////////////////////////////////////////////////
contract CandidateChecklistSafeValidate {
    mapping(uint256 => Checklist) public checklists;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public addsInBlock;
    uint256 public constant MAX_ADDS = 5;

    event ItemAdded(
        uint256 indexed listId,
        string            item,
        CandidateChecklistType ctype,
        CandidateChecklistDefenseType defense
    );
    event Completed(
        uint256 indexed listId,
        CandidateChecklistType ctype,
        CandidateChecklistDefenseType defense
    );

    function addItem(uint256 listId, string calldata item, CandidateChecklistType ctype) external {
        if (bytes(item).length == 0) revert CCL__InvalidItem();

        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]  = block.number;
            addsInBlock[msg.sender] = 0;
        }
        addsInBlock[msg.sender]++;
        if (addsInBlock[msg.sender] > MAX_ADDS) revert CCL__TooManyRequests();

        checklists[listId].items.push(item);
        emit ItemAdded(listId, item, ctype, CandidateChecklistDefenseType.Validation);
    }

    function completeList(uint256 listId, CandidateChecklistType ctype) external {
        checklists[listId].completed = true;
        emit Completed(listId, ctype, CandidateChecklistDefenseType.RateLimit);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & AUDIT LOGGING
//    • ✅ Defense: SignatureValidation – require admin signature  
//               AuditLogging       – record every change
////////////////////////////////////////////////////////////////////////////////
contract CandidateChecklistSafeAdvanced {
    mapping(uint256 => Checklist) public checklists;
    address public signer;

    event AuditLog(
        address indexed who,
        uint256 indexed listId,
        string            item,
        CandidateChecklistDefenseType defense
    );
    event Completed(
        address indexed who,
        uint256 indexed listId,
        CandidateChecklistType ctype,
        CandidateChecklistDefenseType defense
    );

    error CCL__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function addItem(
        uint256 listId,
        string calldata item,
        CandidateChecklistType ctype,
        bytes calldata sig
    ) external {
        bytes32 h = keccak256(abi.encodePacked(listId, item, ctype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert CCL__InvalidSignature();

        checklists[listId].items.push(item);
        emit AuditLog(msg.sender, listId, item, CandidateChecklistDefenseType.SignatureValidation);
    }

    function completeList(
        uint256 listId,
        CandidateChecklistType ctype,
        bytes calldata sig
    ) external {
        bytes32 h = keccak256(abi.encodePacked(listId, ctype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert CCL__InvalidSignature();

        checklists[listId].completed = true;
        emit Completed(msg.sender, listId, ctype, CandidateChecklistDefenseType.AuditLogging);
    }
}
