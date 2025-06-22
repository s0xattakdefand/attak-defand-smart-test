// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DataAccessSuite.sol
/// @notice On‐chain analogues of “Data Access” control patterns:
///   Types: Read, Write, Update, Delete  
///   AttackTypes: UnauthorizedRead, UnauthorizedWrite, DataLeak, Tampering  
///   DefenseTypes: AccessControl, Encryption, Logging, RateLimit, SignatureValidation

enum DataAccessType           { Read, Write, Update, Delete }
enum DataAccessAttackType     { UnauthorizedRead, UnauthorizedWrite, DataLeak, Tampering }
enum DataAccessDefenseType    { AccessControl, Encryption, Logging, RateLimit, SignatureValidation }

error DA__NotAuthorized();
error DA__TooManyRequests();
error DA__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE DATA STORE
//    • ❌ no controls: anyone may read or write → UnauthorizedRead/Write
////////////////////////////////////////////////////////////////////////////////
contract DataAccessVuln {
    mapping(bytes32 => bytes) public store;

    event DataAccessed(
        address indexed who,
        bytes32           key,
        DataAccessType    atype,
        DataAccessAttackType attack
    );

    function writeData(bytes32 key, bytes calldata data, DataAccessType atype) external {
        store[key] = data;
        emit DataAccessed(msg.sender, key, atype, DataAccessAttackType.UnauthorizedWrite);
    }

    function readData(bytes32 key, DataAccessType atype) external view returns (bytes memory) {
        emit DataAccessed(msg.sender, key, atype, DataAccessAttackType.UnauthorizedRead);
        return store[key];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates unauthorized reads, writes, leaks and tampering
////////////////////////////////////////////////////////////////////////////////
contract Attack_DataAccess {
    DataAccessVuln public target;
    bytes32 public lastKey;
    bytes   public lastData;

    constructor(DataAccessVuln _t) { target = _t; }

    function leak(bytes32 key) external {
        bytes memory data = target.readData(key, DataAccessType.Read);
        lastKey = key;
        lastData = data;
    }

    function tamper(bytes32 key, bytes calldata fake) external {
        target.writeData(key, fake, DataAccessType.Write);
    }

    function replayWrite() external {
        target.writeData(lastKey, lastData, DataAccessType.Write);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may read or write
////////////////////////////////////////////////////////////////////////////////
contract DataAccessSafeAC {
    mapping(bytes32 => bytes) public store;
    address public owner;

    event DataAccessed(
        address indexed who,
        bytes32           key,
        DataAccessType    atype,
        DataAccessDefenseType defense
    );

    constructor() { owner = msg.sender; }

    modifier onlyOwner() {
        if (msg.sender != owner) revert DA__NotAuthorized();
        _;
    }

    function writeData(bytes32 key, bytes calldata data, DataAccessType atype) external onlyOwner {
        store[key] = data;
        emit DataAccessed(msg.sender, key, atype, DataAccessDefenseType.AccessControl);
    }
    function readData(bytes32 key, DataAccessType atype) external view onlyOwner returns (bytes memory) {
        emit DataAccessed(msg.sender, key, atype, DataAccessDefenseType.AccessControl);
        return store[key];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH ENCRYPTION & LOGGING
//    • ✅ Defense: Encryption – store only encrypted  
//               Logging    – record every access
////////////////////////////////////////////////////////////////////////////////
contract DataAccessSafeEncrypt {
    mapping(bytes32 => bytes) public store;
    mapping(bytes32 => bytes32) public encryptionKey;
    event DataAccessed(
        address indexed who,
        bytes32           key,
        DataAccessType    atype,
        DataAccessDefenseType defense
    );
    error DA__NotAuthorized();

    function setKey(bytes32 key, bytes32 encKey) external {
        // stub: only admin in real
        encryptionKey[key] = encKey;
    }

    function writeData(bytes32 key, bytes calldata encryptedData, DataAccessType atype) external {
        // assume data is pre‐encrypted off‐chain
        store[key] = encryptedData;
        emit DataAccessed(msg.sender, key, atype, DataAccessDefenseType.Encryption);
    }

    function readData(bytes32 key, DataAccessType atype) external view returns (bytes memory) {
        emit DataAccessed(msg.sender, key, atype, DataAccessDefenseType.Logging);
        return store[key];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH RATE LIMIT & SIGNATURE VALIDATION
//    • ✅ Defense: RateLimit           – cap accesses per block  
//               SignatureValidation   – require off‐chain approval for writes
////////////////////////////////////////////////////////////////////////////////
contract DataAccessSafeAdvanced {
    mapping(bytes32 => bytes) public store;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    address public signer;
    uint256 public constant MAX_CALLS = 5;

    event DataAccessed(
        address indexed who,
        bytes32           key,
        DataAccessType    atype,
        DataAccessDefenseType defense
    );

    error DA__TooManyRequests();
    error DA__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function writeData(
        bytes32 key,
        bytes calldata data,
        DataAccessType atype,
        bytes calldata sig
    ) external {
        // rate-limit writes
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert DA__TooManyRequests();

        // signature must cover (msg.sender||key||data)
        bytes32 h = keccak256(abi.encodePacked(msg.sender, key, data));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DA__InvalidSignature();

        store[key] = data;
        emit DataAccessed(msg.sender, key, atype, DataAccessDefenseType.SignatureValidation);
    }

    function readData(bytes32 key, DataAccessType atype) external view returns (bytes memory) {
        // rate-limit reads
        // (similar logic omitted for brevity)
        emit DataAccessed(msg.sender, key, atype, DataAccessDefenseType.RateLimit);
        return store[key];
    }
}
