// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DataElementSecuritySuite.sol
/// @notice On‐chain analogues for “Data Element” security patterns:
///   Types: Attribute, RecordField, BinaryBlob, RelationalKey, Metadata  
///   AttackTypes: UnauthorizedAccess, DataTampering, Replay, Injection, Overflow  
///   DefenseTypes: AccessControl, IntegrityCheck, RateLimit, SignatureValidation, AuditLogging

enum DataElementType     { Attribute, RecordField, BinaryBlob, RelationalKey, Metadata }
enum DEAttackType         { UnauthorizedAccess, DataTampering, Replay, Injection, Overflow }
enum DEDefenseType        { AccessControl, IntegrityCheck, RateLimit, SignatureValidation, AuditLogging }

error DE__NotAuthorized();
error DE__InvalidInput();
error DE__TooManyRequests();
error DE__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE DATA ELEMENT MANAGER
//    • ❌ no checks: anyone may add/update/read → UnauthorizedAccess/DataTampering
////////////////////////////////////////////////////////////////////////////////
contract DataElementVuln {
    mapping(uint256 => string) public elements;

    event ElementAdded(
        address indexed who,
        uint256           id,
        DataElementType   dtype,
        DEAttackType      attack
    );
    event ElementUpdated(
        address indexed who,
        uint256           id,
        DataElementType   dtype,
        DEAttackType      attack
    );
    event ElementRead(
        address indexed who,
        uint256           id,
        DataElementType   dtype,
        DEAttackType      attack
    );

    function addElement(uint256 id, string calldata data, DataElementType dtype) external {
        elements[id] = data;
        emit ElementAdded(msg.sender, id, dtype, DEAttackType.UnauthorizedAccess);
    }

    function updateElement(uint256 id, string calldata data, DataElementType dtype) external {
        elements[id] = data;
        emit ElementUpdated(msg.sender, id, dtype, DEAttackType.DataTampering);
    }

    function readElement(uint256 id, DataElementType dtype) external view returns (string memory) {
        emit ElementRead(msg.sender, id, dtype, DEAttackType.Replay);
        return elements[id];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates unauthorized access, tampering, replay, injection, overflow
////////////////////////////////////////////////////////////////////////////////
contract Attack_DataElement {
    DataElementVuln public target;
    uint256 public lastId;
    string  public lastData;

    constructor(DataElementVuln _t) {
        target = _t;
    }

    function spoofAdd(uint256 id, string calldata fake) external {
        target.addElement(id, fake, DataElementType.Attribute);
        lastId   = id;
        lastData = fake;
    }

    function poison(uint256 id, string calldata fake) external {
        target.updateElement(id, fake, DataElementType.BinaryBlob);
    }

    function replayRead() external {
        lastData = target.readElement(lastId, DataElementType.RecordField);
    }

    function inject(uint256 id) external {
        // simulate injection via overly long string
        string memory big = new string(1024);
        target.addElement(id, big, DataElementType.Metadata);
    }

    function overflowKey() external {
        // simulate overflow by using max uint
        target.addElement(type(uint256).max, "overflow", DataElementType.RelationalKey);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may add/update/read
////////////////////////////////////////////////////////////////////////////////
contract DataElementSafeAccess {
    mapping(uint256 => string) public elements;
    address public owner;

    event ElementAdded(
        address indexed who,
        uint256           id,
        DataElementType   dtype,
        DEDefenseType     defense
    );
    event ElementUpdated(
        address indexed who,
        uint256           id,
        DataElementType   dtype,
        DEDefenseType     defense
    );
    event ElementRead(
        address indexed who,
        uint256           id,
        DataElementType   dtype,
        DEDefenseType     defense
    );

    constructor() {
        owner = msg.sender;
    }
    modifier onlyOwner() {
        if (msg.sender != owner) revert DE__NotAuthorized();
        _;
    }

    function addElement(uint256 id, string calldata data, DataElementType dtype)
        external onlyOwner
    {
        elements[id] = data;
        emit ElementAdded(msg.sender, id, dtype, DEDefenseType.AccessControl);
    }

    function updateElement(uint256 id, string calldata data, DataElementType dtype)
        external onlyOwner
    {
        elements[id] = data;
        emit ElementUpdated(msg.sender, id, dtype, DEDefenseType.AccessControl);
    }

    function readElement(uint256 id, DataElementType dtype)
        external view onlyOwner returns (string memory)
    {
        emit ElementRead(msg.sender, id, dtype, DEDefenseType.AccessControl);
        return elements[id];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH VALIDATION & RATE LIMIT
//    • ✅ Defense: IntegrityCheck – require nonempty data  
//               RateLimit       – cap ops per block
////////////////////////////////////////////////////////////////////////////////
contract DataElementSafeValidate {
    mapping(uint256 => string) public elements;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public opsInBlock;
    uint256 public constant MAX_OPS = 5;

    event ElementAdded(
        address indexed who,
        uint256           id,
        DataElementType   dtype,
        DEDefenseType     defense
    );
    event ElementUpdated(
        address indexed who,
        uint256           id,
        DataElementType   dtype,
        DEDefenseType     defense
    );
    event ElementRead(
        address indexed who,
        uint256           id,
        DataElementType   dtype,
        DEDefenseType     defense
    );

    error DE__InvalidInput();
    error DE__TooManyRequests();

    modifier rateLimit() {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]   = block.number;
            opsInBlock[msg.sender] = 0;
        }
        opsInBlock[msg.sender]++;
        if (opsInBlock[msg.sender] > MAX_OPS) revert DE__TooManyRequests();
        _;
    }

    function addElement(uint256 id, string calldata data, DataElementType dtype)
        external rateLimit
    {
        if (bytes(data).length == 0) revert DE__InvalidInput();
        elements[id] = data;
        emit ElementAdded(msg.sender, id, dtype, DEDefenseType.IntegrityCheck);
    }

    function updateElement(uint256 id, string calldata data, DataElementType dtype)
        external rateLimit
    {
        if (bytes(data).length == 0) revert DE__InvalidInput();
        elements[id] = data;
        emit ElementUpdated(msg.sender, id, dtype, DEDefenseType.IntegrityCheck);
    }

    function readElement(uint256 id, DataElementType dtype)
        external rateLimit returns (string memory)
    {
        emit ElementRead(msg.sender, id, dtype, DEDefenseType.RateLimit);
        return elements[id];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & AUDIT LOGGING
//    • ✅ Defense: SignatureValidation – require admin‐signed ops  
//               AuditLogging      – record each action
////////////////////////////////////////////////////////////////////////////////
contract DataElementSafeAdvanced {
    mapping(uint256 => string) public elements;
    address public signer;

    event ElementAdded(
        address indexed who,
        uint256           id,
        DataElementType   dtype,
        DEDefenseType     defense
    );
    event ElementUpdated(
        address indexed who,
        uint256           id,
        DataElementType   dtype,
        DEDefenseType     defense
    );
    event ElementRead(
        address indexed who,
        uint256           id,
        DataElementType   dtype,
        DEDefenseType     defense
    );
    event AuditLog(
        address indexed who,
        string            action,
        uint256           id,
        DEDefenseType     defense
    );

    error DE__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function addElement(
        uint256 id,
        string calldata data,
        DataElementType dtype,
        bytes calldata sig
    ) external {
        bytes32 h = keccak256(abi.encodePacked("ADD", msg.sender, id, data, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DE__InvalidSignature();

        elements[id] = data;
        emit ElementAdded(msg.sender, id, dtype, DEDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "addElement", id, DEDefenseType.AuditLogging);
    }

    function updateElement(
        uint256 id,
        string calldata data,
        DataElementType dtype,
        bytes calldata sig
    ) external {
        bytes32 h = keccak256(abi.encodePacked("UPDATE", msg.sender, id, data, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DE__InvalidSignature();

        elements[id] = data;
        emit ElementUpdated(msg.sender, id, dtype, DEDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "updateElement", id, DEDefenseType.AuditLogging);
    }

    function readElement(
        uint256 id,
        DataElementType dtype,
        bytes calldata sig
    ) external returns (string memory) {
        bytes32 h = keccak256(abi.encodePacked("READ", msg.sender, id, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DE__InvalidSignature();

        string memory d = elements[id];
        emit ElementRead(msg.sender, id, dtype, DEDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "readElement", id, DEDefenseType.AuditLogging);
        return d;
    }
}
