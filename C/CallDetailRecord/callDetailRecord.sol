// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title CallDetailRecordSuite.sol
/// @notice On‐chain analogues of “Call Detail Record” (CDR) workflows:
///   Types: Voice, SMS, Data, Roaming  
///   AttackTypes: DataTampering, RecordDeletion, ReplayAttack, PrivacyLeak  
///   DefenseTypes: AccessControl, ImmutableLog, SignatureValidation, RateLimit

enum CDRType             { Voice, SMS, Data, Roaming }
enum CDRAttackType       { DataTampering, RecordDeletion, ReplayAttack, PrivacyLeak }
enum CDRDefenseType      { AccessControl, ImmutableLog, SignatureValidation, RateLimit }

error CDR__NotAuthorized();
error CDR__Immutable();
error CDR__InvalidSignature();
error CDR__TooManyRequests();

struct CDR {
    address caller;
    address callee;
    uint256 timestamp;
    uint256 duration;
}

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE CDR MANAGER
//    • ❌ no protections: records can be tampered or deleted → DataTampering
////////////////////////////////////////////////////////////////////////////////
contract CDRVuln {
    mapping(bytes32 => CDR) public records;

    event CDRRecorded(
        address indexed who,
        bytes32         recordId,
        CDRType         dtype,
        CDRAttackType   attack
    );

    function recordCDR(
        bytes32 recordId,
        address caller,
        address callee,
        uint256 timestamp,
        uint256 duration,
        CDRType dtype
    ) external {
        records[recordId] = CDR(caller, callee, timestamp, duration);
        emit CDRRecorded(msg.sender, recordId, dtype, CDRAttackType.DataTampering);
    }

    function deleteCDR(bytes32 recordId, CDRType dtype) external {
        delete records[recordId];
        emit CDRRecorded(msg.sender, recordId, dtype, CDRAttackType.RecordDeletion);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates tampering, deletion, and replay
////////////////////////////////////////////////////////////////////////////////
contract Attack_CDR {
    CDRVuln public target;
    bytes32 public lastId;
    CDR     public lastRecord;
    CDRType public lastType;

    constructor(CDRVuln _t) {
        target = _t;
    }

    function capture(bytes32 recordId, CDRType dtype) external {
        CDR memory rec = target.records(recordId);
        lastId     = recordId;
        lastRecord = rec;
        lastType   = dtype;
    }

    function tamper(bytes32 recordId, CDRType dtype, CDR calldata fake) external {
        target.recordCDR(recordId, fake.caller, fake.callee, fake.timestamp, fake.duration, dtype);
    }

    function deleteRecord(bytes32 recordId, CDRType dtype) external {
        target.deleteCDR(recordId, dtype);
    }

    function replay() external {
        target.recordCDR(
            lastId,
            lastRecord.caller,
            lastRecord.callee,
            lastRecord.timestamp,
            lastRecord.duration,
            lastType
        );
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only admin may record or delete
////////////////////////////////////////////////////////////////////////////////
contract CDRSafeAccess {
    mapping(bytes32 => CDR) public records;
    address public admin;

    event CDRRecorded(
        address indexed who,
        bytes32         recordId,
        CDRType         dtype,
        CDRDefenseType  defense
    );

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        if (msg.sender != admin) revert CDR__NotAuthorized();
        _;
    }

    function recordCDR(
        bytes32 recordId,
        address caller,
        address callee,
        uint256 timestamp,
        uint256 duration,
        CDRType dtype
    ) external onlyAdmin {
        records[recordId] = CDR(caller, callee, timestamp, duration);
        emit CDRRecorded(msg.sender, recordId, dtype, CDRDefenseType.AccessControl);
    }

    function deleteCDR(bytes32 recordId, CDRType dtype) external onlyAdmin {
        delete records[recordId];
        emit CDRRecorded(msg.sender, recordId, dtype, CDRDefenseType.AccessControl);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH IMMUTABLE LOG
//    • ✅ Defense: ImmutableLog – once recorded, cannot modify or delete
////////////////////////////////////////////////////////////////////////////////
contract CDRSafeImmutable {
    mapping(bytes32 => CDR) public records;
    mapping(bytes32 => bool) public exists;

    event CDRRecorded(
        address indexed who,
        bytes32         recordId,
        CDRType         dtype,
        CDRDefenseType  defense
    );

    function recordCDR(
        bytes32 recordId,
        address caller,
        address callee,
        uint256 timestamp,
        uint256 duration,
        CDRType dtype
    ) external {
        if (exists[recordId]) revert CDR__Immutable();
        records[recordId] = CDR(caller, callee, timestamp, duration);
        exists[recordId]  = true;
        emit CDRRecorded(msg.sender, recordId, dtype, CDRDefenseType.ImmutableLog);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & RATE LIMIT
//    • ✅ Defense: SignatureValidation – verify recorder’s signature  
//               RateLimit           – cap recordings per block per sender
////////////////////////////////////////////////////////////////////////////////
contract CDRSafeAdvanced {
    mapping(bytes32 => CDR) public records;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    address public signer;
    uint256 public constant MAX_CALLS = 5;

    event CDRRecorded(
        address indexed who,
        bytes32         recordId,
        CDRType         dtype,
        CDRDefenseType  defense
    );

    constructor(address _signer) {
        signer = _signer;
    }

    function recordCDR(
        bytes32 recordId,
        address caller,
        address callee,
        uint256 timestamp,
        uint256 duration,
        CDRType dtype,
        bytes calldata sig
    ) external {
        // rate-limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert CDR__TooManyRequests();

        // verify signature over payload
        bytes32 h = keccak256(abi.encodePacked(recordId, caller, callee, timestamp, duration, dtype));
        bytes32 ethMsg = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(ethMsg, v, r, s) != signer) revert CDR__InvalidSignature();

        records[recordId] = CDR(caller, callee, timestamp, duration);
        emit CDRRecorded(msg.sender, recordId, dtype, CDRDefenseType.SignatureValidation);
    }
}
