// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DataInTransitSecuritySuite.sol
/// @notice On‐chain analogues for “Data In Transit” security patterns:
///   Types: Unencrypted, Encrypted, OverSSL, OverHTTPS, CustomProtocol  
///   AttackTypes: Eavesdropping, MITM, Replay, Injection  
///   DefenseTypes: TLS, Authentication, AntiReplay, IntegrityCheck, RateLimit

enum DITType             { Unencrypted, Encrypted, OverSSL, OverHTTPS, CustomProtocol }
enum DITAttackType       { Eavesdropping, MITM, Replay, Injection }
enum DITDefenseType      { TLS, Authentication, AntiReplay, IntegrityCheck, RateLimit }

error DIT__NotAuthorized();
error DIT__TooManyRequests();
error DIT__InvalidSignature();
error DIT__InvalidData();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE CHANNEL
//    • ❌ no protections: data sent in plaintext → Eavesdropping, MITM
////////////////////////////////////////////////////////////////////////////////
contract DataInTransitVuln {
    event DataSent(
        address indexed from,
        address indexed to,
        string            payload,
        DITType           dtype,
        DITAttackType     attack
    );
    event DataReceived(
        address indexed from,
        address indexed to,
        string            payload,
        DITType           dtype,
        DITAttackType     attack
    );

    function sendData(address to, string calldata payload, DITType dtype) external {
        emit DataSent(msg.sender, to, payload, dtype, DITAttackType.Eavesdropping);
    }

    function receiveData(address from, string calldata payload, DITType dtype) external {
        emit DataReceived(from, msg.sender, payload, dtype, DITAttackType.MITM);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates sniffing, MITM, replay, injection
////////////////////////////////////////////////////////////////////////////////
contract Attack_DataInTransit {
    DataInTransitVuln public channel;
    string public lastPayload;
    address public lastFrom;
    address public lastTo;

    constructor(DataInTransitVuln _c) { channel = _c; }

    function sniff(address from, address to, string calldata payload) external {
        // capture plaintext
        lastFrom = from;
        lastTo = to;
        lastPayload = payload;
        channel.DataSent(from, to, payload, DITType.Unencrypted, DITAttackType.Eavesdropping);
    }

    function mitm(address from, address to, string calldata fake) external {
        // intercept and inject
        channel.sendData(to, fake, DITType.Unencrypted);
    }

    function replay() external {
        // replay previous message
        channel.sendData(lastTo, lastPayload, DITType.Unencrypted);
    }

    function inject(address to, string calldata payload) external {
        channel.sendData(to, payload, DITType.Unencrypted);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL (TLS SIMULATION)
//    • ✅ Defense: TLS – only owner may send/receive secure
////////////////////////////////////////////////////////////////////////////////
contract DataInTransitSafeAccess {
    address public owner;
    event DataSent(
        address indexed from,
        address indexed to,
        string            payload,
        DITType           dtype,
        DITDefenseType    defense
    );
    event DataReceived(
        address indexed from,
        address indexed to,
        string            payload,
        DITType           dtype,
        DITDefenseType    defense
    );

    constructor() { owner = msg.sender; }
    modifier onlyOwner() {
        if (msg.sender != owner) revert DIT__NotAuthorized();
        _;
    }

    function sendData(address to, string calldata payload, DITType dtype) external onlyOwner {
        emit DataSent(msg.sender, to, payload, dtype, DITDefenseType.TLS);
    }

    function receiveData(address from, string calldata payload, DITType dtype) external onlyOwner {
        emit DataReceived(from, msg.sender, payload, dtype, DITDefenseType.TLS);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH VALIDATION & RATE LIMIT
//    • ✅ Defense: IntegrityCheck – require nonempty payload  
//               RateLimit       – cap sends per block
////////////////////////////////////////////////////////////////////////////////
contract DataInTransitSafeValidate {
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public opsInBlock;
    uint256 public constant MAX_OPS = 3;

    event DataSent(
        address indexed from,
        address indexed to,
        string            payload,
        DITType           dtype,
        DITDefenseType    defense
    );
    event DataReceived(
        address indexed from,
        address indexed to,
        string            payload,
        DITType           dtype,
        DITDefenseType    defense
    );

    error DIT__InvalidData();
    error DIT__TooManyRequests();

    modifier rateLimit() {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]   = block.number;
            opsInBlock[msg.sender] = 0;
        }
        opsInBlock[msg.sender]++;
        if (opsInBlock[msg.sender] > MAX_OPS) revert DIT__TooManyRequests();
        _;
    }

    function sendData(address to, string calldata payload, DITType dtype)
        external rateLimit
    {
        if (bytes(payload).length == 0) revert DIT__InvalidData();
        emit DataSent(msg.sender, to, payload, dtype, DITDefenseType.IntegrityCheck);
    }

    function receiveData(address from, string calldata payload, DITType dtype)
        external rateLimit
    {
        if (bytes(payload).length == 0) revert DIT__InvalidData();
        emit DataReceived(from, msg.sender, payload, dtype, DITDefenseType.RateLimit);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & ANTI‐REPLAY
//    • ✅ Defense: Authentication – require signed payload  
//               AntiReplay – track nonces to prevent replay
////////////////////////////////////////////////////////////////////////////////
contract DataInTransitSafeAdvanced {
    address public signer;
    mapping(bytes32 => bool) public seen;

    event DataSent(
        address indexed from,
        address indexed to,
        string            payload,
        DITType           dtype,
        DITDefenseType    defense
    );
    event DataReceived(
        address indexed from,
        address indexed to,
        string            payload,
        DITType           dtype,
        DITDefenseType    defense
    );

    error DIT__InvalidSignature();
    error DIT__ReplayDetected();

    constructor(address _signer) { signer = _signer; }

    function sendData(
        address to,
        string calldata payload,
        DITType dtype,
        uint256 nonce,
        bytes calldata sig
    ) external {
        bytes32 h = keccak256(abi.encodePacked(msg.sender, to, payload, dtype, nonce));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DIT__InvalidSignature();
        if (seen[h]) revert DIT__ReplayDetected();
        seen[h] = true;

        emit DataSent(msg.sender, to, payload, dtype, DITDefenseType.Authentication);
    }

    function receiveData(
        address from,
        string calldata payload,
        DITType dtype,
        uint256 nonce,
        bytes calldata sig
    ) external {
        bytes32 h = keccak256(abi.encodePacked(from, msg.sender, payload, dtype, nonce));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DIT__InvalidSignature();
        if (seen[h]) revert DIT__ReplayDetected();
        seen[h] = true;

        emit DataReceived(from, msg.sender, payload, dtype, DITDefenseType.AntiReplay);
    }
}
