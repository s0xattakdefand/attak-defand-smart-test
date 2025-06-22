// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title WorkingDraftSuite.sol
/// @notice On‐chain analogues of “Working Draft” document lifecycle patterns:
///   Types: Public, Internal, Proposed, Archived  
///   AttackTypes: Tampering, PrematurePublishing, UnauthorizedAccess, Replay  
///   DefenseTypes: ImmutableStorage, AccessControl, VersionLock, AuditLogging

enum WorkingDraftType         { Public, Internal, Proposed, Archived }
enum WorkingDraftAttackType   { Tampering, PrematurePublishing, UnauthorizedAccess, Replay }
enum WorkingDraftDefenseType  { ImmutableStorage, AccessControl, VersionLock, AuditLogging }

error WD__AlreadyInitialized();
error WD__NotAuthorized();
error WD__VersionLocked();
error WD__TooManyRequests();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE DRAFT STORE
//    • ❌ no controls: any caller may overwrite or read → Tampering, UnauthorizedAccess
////////////////////////////////////////////////////////////////////////////////
contract WorkingDraftVuln {
    mapping(uint256 => string) public draft;
    event DraftSaved(
        address indexed who,
        uint256           draftId,
        WorkingDraftType  dtype,
        string            content,
        WorkingDraftAttackType attack
    );
    event DraftRetrieved(
        address indexed who,
        uint256           draftId,
        WorkingDraftType  dtype,
        string            content,
        WorkingDraftAttackType attack
    );

    function saveDraft(
        uint256 draftId,
        WorkingDraftType dtype,
        string calldata content
    ) external {
        draft[draftId] = content;
        emit DraftSaved(msg.sender, draftId, dtype, content, WorkingDraftAttackType.Tampering);
    }

    function retrieveDraft(
        uint256 draftId,
        WorkingDraftType dtype
    ) external {
        emit DraftRetrieved(msg.sender, draftId, dtype, draft[draftId], WorkingDraftAttackType.UnauthorizedAccess);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates tampering and replay of drafts
////////////////////////////////////////////////////////////////////////////////
contract Attack_WorkingDraft {
    WorkingDraftVuln public target;
    uint256 public lastId;
    string  public lastContent;
    WorkingDraftType public lastType;

    constructor(WorkingDraftVuln _t) { target = _t; }

    function tamper(
        uint256 draftId,
        string calldata fakeContent
    ) external {
        target.saveDraft(draftId, WorkingDraftType.Public, fakeContent);
    }

    function capture(uint256 draftId, WorkingDraftType dtype) external {
        lastId = draftId;
        lastContent = target.draft(draftId);
        lastType = dtype;
    }

    function replay() external {
        target.saveDraft(lastId, lastType, lastContent);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH IMMUTABLE STORAGE
//    • ✅ Defense: ImmutableStorage – once saved, draft cannot change
////////////////////////////////////////////////////////////////////////////////
contract WorkingDraftSafeImmutable {
    mapping(uint256 => string) public draft;
    mapping(uint256 => bool)   private initialized;

    event DraftSaved(
        address indexed who,
        uint256           draftId,
        string            content,
        WorkingDraftDefenseType defense
    );

    function saveDraft(uint256 draftId, string calldata content) external {
        if (initialized[draftId]) revert WD__AlreadyInitialized();
        draft[draftId] = content;
        initialized[draftId] = true;
        emit DraftSaved(msg.sender, draftId, content, WorkingDraftDefenseType.ImmutableStorage);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only authorized editors may save
////////////////////////////////////////////////////////////////////////////////
contract WorkingDraftSafeAccess {
    mapping(address => bool) public editors;
    mapping(uint256 => string) public draft;

    event DraftSaved(
        address indexed who,
        uint256           draftId,
        string            content,
        WorkingDraftDefenseType defense
    );

    error WD__NotAuthorized();

    constructor() {
        editors[msg.sender] = true;
    }

    function setEditor(address user, bool ok) external {
        require(editors[msg.sender], "admin only");
        editors[user] = ok;
    }

    function saveDraft(uint256 draftId, string calldata content) external {
        if (!editors[msg.sender]) revert WD__NotAuthorized();
        draft[draftId] = content;
        emit DraftSaved(msg.sender, draftId, content, WorkingDraftDefenseType.AccessControl);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH VERSION LOCK & AUDIT LOGGING
//    • ✅ Defense: VersionLock – only higher‐version saves  
//               AuditLogging – record every save
////////////////////////////////////////////////////////////////////////////////
contract WorkingDraftSafeAdvanced {
    struct Entry { string content; uint256 version; }
    mapping(uint256 => Entry) public draft;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MAX_CALLS = 3;

    event AuditLog(
        address indexed who,
        uint256           draftId,
        WorkingDraftDefenseType defense
    );
    event DraftSaved(
        address indexed who,
        uint256           draftId,
        string            content,
        WorkingDraftDefenseType defense
    );

    error WD__TooManyRequests();

    function saveDraft(
        uint256 draftId,
        string calldata content,
        uint256 version
    ) external {
        // rate‐limit per user
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender] = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert WD__TooManyRequests();

        // version lock
        if (draft[draftId].version >= version) revert WD__VersionLocked();

        // audit and save
        emit AuditLog(msg.sender, draftId, WorkingDraftDefenseType.AuditLogging);
        draft[draftId] = Entry(content, version);
        emit DraftSaved(msg.sender, draftId, content, WorkingDraftDefenseType.VersionLock);
    }
}
