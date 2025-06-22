// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DataBlockSecuritySuite.sol
/// @notice On‐chain analogues for “Data Block” security patterns:
///   Types: SingleBlock, MultiChainBlock, SparseBlock, EncryptedBlock  
///   AttackTypes: UnauthorizedAccess, Tampering, Replay, Overflow  
///   DefenseTypes: AccessControl, IntegrityCheck, RateLimit, Encryption, SignatureValidation

enum DataBlockType       { SingleBlock, MultiChainBlock, SparseBlock, EncryptedBlock }
enum DBAttackType        { UnauthorizedAccess, Tampering, Replay, Overflow }
enum DBDefenseType       { AccessControl, IntegrityCheck, RateLimit, Encryption, SignatureValidation }

error DB__NotAuthorized();
error DB__InvalidInput();
error DB__TooManyRequests();
error DB__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE DATA BLOCK MANAGER
//    • ❌ no checks: anyone may store, update, or read → UnauthorizedAccess/Tampering
////////////////////////////////////////////////////////////////////////////////
contract DataBlockVuln {
    mapping(uint256 => bytes) public blocks;

    event BlockStored(
        address indexed who,
        uint256 indexed blockId,
        DataBlockType dtype,
        DBAttackType attack
    );
    event BlockUpdated(
        address indexed who,
        uint256 indexed blockId,
        DataBlockType dtype,
        DBAttackType attack
    );
    event BlockRetrieved(
        address indexed who,
        uint256 indexed blockId,
        DataBlockType dtype,
        DBAttackType attack
    );

    function storeBlock(
        uint256 blockId,
        bytes calldata data,
        DataBlockType dtype
    ) external {
        blocks[blockId] = data;
        emit BlockStored(msg.sender, blockId, dtype, DBAttackType.UnauthorizedAccess);
    }

    function updateBlock(
        uint256 blockId,
        bytes calldata data,
        DataBlockType dtype
    ) external {
        blocks[blockId] = data;
        emit BlockUpdated(msg.sender, blockId, dtype, DBAttackType.Tampering);
    }

    function retrieveBlock(
        uint256 blockId,
        DataBlockType dtype
    ) external view returns (bytes memory) {
        emit BlockRetrieved(msg.sender, blockId, dtype, DBAttackType.Replay);
        return blocks[blockId];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates unauthorized store, tampering, replay, overflow
////////////////////////////////////////////////////////////////////////////////
contract Attack_DataBlock {
    DataBlockVuln public target;
    uint256 public lastId;
    bytes  public lastData;

    constructor(DataBlockVuln _t) {
        target = _t;
    }

    function spoofStore(uint256 blockId, bytes calldata fake) external {
        target.storeBlock(blockId, fake, DataBlockType.SingleBlock);
        lastId   = blockId;
        lastData = fake;
    }

    function tamper(uint256 blockId, bytes calldata fake) external {
        target.updateBlock(blockId, fake, DataBlockType.SparseBlock);
    }

    function leak(uint256 blockId) external {
        lastData = target.retrieveBlock(blockId, DataBlockType.SingleBlock);
    }

    function replayStore() external {
        target.storeBlock(lastId, lastData, DataBlockType.SingleBlock);
    }

    function overflowStore() external {
        // attempt very large blockId to simulate overflow scenario
        target.storeBlock(type(uint256).max, hex"", DataBlockType.MultiChainBlock);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may store/update/read
////////////////////////////////////////////////////////////////////////////////
contract DataBlockSafeAccess {
    mapping(uint256 => bytes) public blocks;
    address public owner;

    event BlockStored(
        address indexed who,
        uint256 indexed blockId,
        DataBlockType dtype,
        DBDefenseType defense
    );
    event BlockUpdated(
        address indexed who,
        uint256 indexed blockId,
        DataBlockType dtype,
        DBDefenseType defense
    );
    event BlockRetrieved(
        address indexed who,
        uint256 indexed blockId,
        DataBlockType dtype,
        DBDefenseType defense
    );

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert DB__NotAuthorized();
        _;
    }

    function storeBlock(
        uint256 blockId,
        bytes calldata data,
        DataBlockType dtype
    ) external onlyOwner {
        blocks[blockId] = data;
        emit BlockStored(msg.sender, blockId, dtype, DBDefenseType.AccessControl);
    }

    function updateBlock(
        uint256 blockId,
        bytes calldata data,
        DataBlockType dtype
    ) external onlyOwner {
        blocks[blockId] = data;
        emit BlockUpdated(msg.sender, blockId, dtype, DBDefenseType.AccessControl);
    }

    function retrieveBlock(
        uint256 blockId,
        DataBlockType dtype
    ) external view onlyOwner returns (bytes memory) {
        emit BlockRetrieved(msg.sender, blockId, dtype, DBDefenseType.AccessControl);
        return blocks[blockId];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH VALIDATION & RATE LIMIT
//    • ✅ Defense: IntegrityCheck – require nonempty data  
//               RateLimit       – cap ops per block
////////////////////////////////////////////////////////////////////////////////
contract DataBlockSafeValidate {
    mapping(uint256 => bytes) public blocks;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public opsInBlock;
    uint256 public constant MAX_OPS = 5;

    event BlockStored(
        address indexed who,
        uint256 indexed blockId,
        DataBlockType dtype,
        DBDefenseType defense
    );
    event BlockUpdated(
        address indexed who,
        uint256 indexed blockId,
        DataBlockType dtype,
        DBDefenseType defense
    );
    event BlockRetrieved(
        address indexed who,
        uint256 indexed blockId,
        DataBlockType dtype,
        DBDefenseType defense
    );

    error DB__InvalidInput();
    error DB__TooManyRequests();

    modifier rateLimit() {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            opsInBlock[msg.sender] = 0;
        }
        opsInBlock[msg.sender]++;
        if (opsInBlock[msg.sender] > MAX_OPS) revert DB__TooManyRequests();
        _;
    }

    function storeBlock(
        uint256 blockId,
        bytes calldata data,
        DataBlockType dtype
    ) external rateLimit {
        if (data.length == 0) revert DB__InvalidInput();
        blocks[blockId] = data;
        emit BlockStored(msg.sender, blockId, dtype, DBDefenseType.IntegrityCheck);
    }

    function updateBlock(
        uint256 blockId,
        bytes calldata data,
        DataBlockType dtype
    ) external rateLimit {
        if (data.length == 0) revert DB__InvalidInput();
        blocks[blockId] = data;
        emit BlockUpdated(msg.sender, blockId, dtype, DBDefenseType.IntegrityCheck);
    }

    function retrieveBlock(
        uint256 blockId,
        DataBlockType dtype
    ) external rateLimit returns (bytes memory) {
        bytes memory d = blocks[blockId];
        emit BlockRetrieved(msg.sender, blockId, dtype, DBDefenseType.RateLimit);
        return d;
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & AUDIT LOGGING
//    • ✅ Defense: SignatureValidation – require admin‐signed ops  
//               AuditLogging      – record each action
////////////////////////////////////////////////////////////////////////////////
contract DataBlockSafeAdvanced {
    mapping(uint256 => bytes) public blocks;
    address public signer;

    event BlockStored(
        address indexed who,
        uint256 indexed blockId,
        DataBlockType dtype,
        DBDefenseType defense
    );
    event BlockUpdated(
        address indexed who,
        uint256 indexed blockId,
        DataBlockType dtype,
        DBDefenseType defense
    );
    event BlockRetrieved(
        address indexed who,
        uint256 indexed blockId,
        DataBlockType dtype,
        DBDefenseType defense
    );
    event AuditLog(
        address indexed who,
        string            action,
        uint256           blockId,
        DBDefenseType     defense
    );

    error DB__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function storeBlock(
        uint256 blockId,
        bytes calldata data,
        DataBlockType dtype,
        bytes calldata sig
    ) external {
        bytes32 h = keccak256(abi.encodePacked("STORE", blockId, data, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DB__InvalidSignature();

        blocks[blockId] = data;
        emit BlockStored(msg.sender, blockId, dtype, DBDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "storeBlock", blockId, DBDefenseType.AuditLogging);
    }

    function updateBlock(
        uint256 blockId,
        bytes calldata data,
        DataBlockType dtype,
        bytes calldata sig
    ) external {
        bytes32 h = keccak256(abi.encodePacked("UPDATE", blockId, data, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DB__InvalidSignature();

        blocks[blockId] = data;
        emit BlockUpdated(msg.sender, blockId, dtype, DBDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "updateBlock", blockId, DBDefenseType.AuditLogging);
    }

    function retrieveBlock(
        uint256 blockId,
        DataBlockType dtype,
        bytes calldata sig
    ) external returns (bytes memory) {
        bytes32 h = keccak256(abi.encodePacked("RETRIEVE", blockId, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DB__InvalidSignature();

        bytes memory d = blocks[blockId];
        emit BlockRetrieved(msg.sender, blockId, dtype, DBDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "retrieveBlock", blockId, DBDefenseType.AuditLogging);
        return d;
    }
}
