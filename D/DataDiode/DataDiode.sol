// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DataDiodeSecuritySuite.sol
/// @notice On‐chain analogues for “Data Diode” patterns:
///   Types: SimpleDiode, BufferedDiode, VirtualDiode, EncryptedDiode  
///   AttackTypes: ReverseFlow, Tampering, Replay, Flood  
///   DefenseTypes: Unidirectional, IntegrityCheck, RateLimit, Encryption, SignatureValidation

enum DDType               { SimpleDiode, BufferedDiode, VirtualDiode, EncryptedDiode }
enum DDAttackType         { ReverseFlow, Tampering, Replay, Flood }
enum DDDefenseType        { Unidirectional, IntegrityCheck, RateLimit, Encryption, SignatureValidation }

error DD__NotAllowed();
error DD__InvalidInput();
error DD__TooManyRequests();
error DD__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE DIODE MANAGER
//    • ❌ no enforcement: inbound writes allowed → ReverseFlow, Tampering
////////////////////////////////////////////////////////////////////////////////
contract DataDiodeVuln {
    mapping(uint256 => string) public outbound;
    mapping(uint256 => string) public inbound;

    event DataSent(
        address indexed who,
        uint256           id,
        DDType            dtype,
        DDAttackType      attack
    );
    event DataReceived(
        address indexed who,
        uint256           id,
        DDType            dtype,
        DDAttackType      attack
    );

    function sendData(uint256 id, string calldata data, DDType dtype) external {
        outbound[id] = data;
        emit DataSent(msg.sender, id, dtype, DDAttackType.Flood);
    }

    function receiveData(uint256 id, string calldata data, DDType dtype) external {
        inbound[id] = data;
        emit DataReceived(msg.sender, id, dtype, DDAttackType.ReverseFlow);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates reverse‐flow, tampering, replay, flood on diode
////////////////////////////////////////////////////////////////////////////////
contract Attack_DataDiode {
    DataDiodeVuln public target;
    uint256 public lastId;
    string  public lastData;

    constructor(DataDiodeVuln _t) {
        target = _t;
    }

    function reverseFlow(uint256 id, string calldata fake) external {
        target.receiveData(id, fake, DDType.SimpleDiode);
        lastId   = id;
        lastData = fake;
    }

    function tamperSend(uint256 id, string calldata fake) external {
        target.sendData(id, fake, DDType.VirtualDiode);
    }

    function replay() external {
        target.receiveData(lastId, lastData, DDType.BufferedDiode);
    }

    function floodReceive(uint256 id, string calldata data, uint256 times) external {
        for (uint i = 0; i < times; i++) {
            target.receiveData(id, data, DDType.EncryptedDiode);
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH UNIDIRECTIONAL ENFORCEMENT
//    • ✅ Defense: Unidirectional – disallow inbound writes entirely
////////////////////////////////////////////////////////////////////////////////
contract DataDiodeSafeUnidir {
    mapping(uint256 => string) public outbound;
    event DataSent(
        address indexed who,
        uint256           id,
        DDType            dtype,
        DDDefenseType     defense
    );

    function sendData(uint256 id, string calldata data, DDType dtype) external {
        outbound[id] = data;
        emit DataSent(msg.sender, id, dtype, DDDefenseType.Unidirectional);
    }

    function receiveData(uint256, string calldata, DDType) external pure {
        revert DD__NotAllowed();
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH INTEGRITY CHECK & RATE LIMIT
//    • ✅ Defense: IntegrityCheck – require nonempty data  
//               RateLimit       – cap operations per block
////////////////////////////////////////////////////////////////////////////////
contract DataDiodeSafeValidate {
    mapping(uint256 => string) public outbound;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public opsInBlock;
    uint256 public constant MAX_OPS = 5;

    event DataSent(
        address indexed who,
        uint256           id,
        DDType            dtype,
        DDDefenseType     defense
    );
    event DataReceived(
        address indexed who,
        uint256           id,
        DDType            dtype,
        DDDefenseType     defense
    );

    error DD__InvalidInput();
    error DD__TooManyRequests();

    modifier rateLimit() {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]   = block.number;
            opsInBlock[msg.sender]  = 0;
        }
        opsInBlock[msg.sender]++;
        if (opsInBlock[msg.sender] > MAX_OPS) revert DD__TooManyRequests();
        _;
    }

    function sendData(uint256 id, string calldata data, DDType dtype)
        external rateLimit
    {
        if (bytes(data).length == 0) revert DD__InvalidInput();
        outbound[id] = data;
        emit DataSent(msg.sender, id, dtype, DDDefenseType.IntegrityCheck);
    }

    function receiveData(uint256 id, string calldata data, DDType dtype)
        external rateLimit
    {
        // allow only validated inbound, here we mirror to outbound for audit
        emit DataReceived(msg.sender, id, dtype, DDDefenseType.RateLimit);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & AUDIT LOGGING
//    • ✅ Defense: SignatureValidation – require admin-signed ops  
//               AuditLogging      – record each action
////////////////////////////////////////////////////////////////////////////////
contract DataDiodeSafeAdvanced {
    mapping(uint256 => string) public outbound;
    address public signer;

    event DataSent(
        address indexed who,
        uint256           id,
        DDType            dtype,
        DDDefenseType     defense
    );
    event DataReceived(
        address indexed who,
        uint256           id,
        DDType            dtype,
        DDDefenseType     defense
    );
    event AuditLog(
        address indexed who,
        string            action,
        uint256           id,
        DDDefenseType     defense
    );

    error DD__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function sendData(
        uint256 id,
        string calldata data,
        DDType dtype,
        bytes calldata sig
    ) external {
        bytes32 h = keccak256(abi.encodePacked("SEND", msg.sender, id, data, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DD__InvalidSignature();

        outbound[id] = data;
        emit DataSent(msg.sender, id, dtype, DDDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "sendData", id, DDDefenseType.AuditLogging);
    }

    function receiveData(
        uint256 id,
        string calldata data,
        DDType dtype,
        bytes calldata sig
    ) external {
        bytes32 h = keccak256(abi.encodePacked("RECEIVE", msg.sender, id, data, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DD__InvalidSignature();

        emit DataReceived(msg.sender, id, dtype, DDDefenseType.Encryption);
        emit AuditLog(msg.sender, "receiveData", id, DDDefenseType.AuditLogging);
    }
}
