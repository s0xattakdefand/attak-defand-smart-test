// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title CallProcessorSuite.sol
/// @notice On‐chain analogues of “Call Processor” workflows:
///   Types: Inbound, Outbound, IVR, Conference  
///   AttackTypes: Eavesdropping, CallInjection, Replay, DenialOfService  
///   DefenseTypes: AccessControl, Encryption, RateLimit, SignatureValidation, Monitoring

enum CallProcessorType         { Inbound, Outbound, IVR, Conference }
enum CallProcessorAttackType   { Eavesdropping, CallInjection, Replay, DenialOfService }
enum CallProcessorDefenseType  { AccessControl, Encryption, RateLimit, SignatureValidation, Monitoring }

error CP__NotOwner();
error CP__InvalidDuration();
error CP__TooManyRequests();
error CP__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE CALL PROCESSOR
//    • ❌ no controls: any caller may inject or replay → CallInjection
////////////////////////////////////////////////////////////////////////////////
contract CallProcessorVuln {
    struct Call { address from; address to; uint256 duration; }

    mapping(bytes32 => Call) public calls;
    event CallProcessed(
        address indexed who,
        bytes32           callId,
        CallProcessorType ctype,
        CallProcessorAttackType attack
    );

    function processCall(
        bytes32 callId,
        address from,
        address to,
        uint256 duration,
        CallProcessorType ctype
    ) external {
        calls[callId] = Call(from, to, duration);
        emit CallProcessed(msg.sender, callId, ctype, CallProcessorAttackType.CallInjection);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates injection, replay, DoS via rapid calls
////////////////////////////////////////////////////////////////////////////////
contract Attack_CallProcessor {
    CallProcessorVuln public target;
    bytes32 public lastId;
    address public lastFrom;
    address public lastTo;
    uint256 public lastDuration;
    CallProcessorType public lastType;

    constructor(CallProcessorVuln _t) { target = _t; }

    function inject(
        bytes32 callId,
        address from,
        address to,
        uint256 duration
    ) external {
        target.processCall(callId, from, to, duration, CallProcessorType.Inbound);
        lastId = callId; lastFrom = from; lastTo = to; lastDuration = duration; lastType = CallProcessorType.Inbound;
    }

    function replay() external {
        target.processCall(lastId, lastFrom, lastTo, lastDuration, lastType);
    }

    function flood(bytes32 baseId, address from, address to, uint256 n) external {
        for (uint256 i = 0; i < n; i++) {
            bytes32 id = keccak256(abi.encodePacked(baseId, i));
            target.processCall(id, from, to, 0, CallProcessorType.Outbound);
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may process calls
////////////////////////////////////////////////////////////////////////////////
contract CallProcessorSafeAccess {
    struct Call { address from; address to; uint256 duration; }

    mapping(bytes32 => Call) public calls;
    address public owner;

    event CallProcessed(
        address indexed who,
        bytes32           callId,
        CallProcessorType ctype,
        CallProcessorDefenseType defense
    );

    modifier onlyOwner() {
        if (msg.sender != owner) revert CP__NotOwner();
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function processCall(
        bytes32 callId,
        address from,
        address to,
        uint256 duration,
        CallProcessorType ctype
    ) external onlyOwner {
        calls[callId] = Call(from, to, duration);
        emit CallProcessed(msg.sender, callId, ctype, CallProcessorDefenseType.AccessControl);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH VALIDATION & RATE LIMIT
//    • ✅ Defense: RangeCheck – duration must be within bounds  
//               RateLimit – cap calls per block per sender
////////////////////////////////////////////////////////////////////////////////
contract CallProcessorSafeValidate {
    struct Call { address from; address to; uint256 duration; }

    mapping(bytes32 => Call) public calls;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;

    uint256 public constant MIN_DURATION = 1;      // 1 second
    uint256 public constant MAX_DURATION = 3600;   // 1 hour
    uint256 public constant MAX_CALLS    = 5;

    event CallProcessed(
        address indexed who,
        bytes32           callId,
        CallProcessorType ctype,
        CallProcessorDefenseType defense
    );

    function processCall(
        bytes32 callId,
        address from,
        address to,
        uint256 duration,
        CallProcessorType ctype
    ) external {
        if (duration < MIN_DURATION || duration > MAX_DURATION) revert CP__InvalidDuration();

        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert CP__TooManyRequests();

        calls[callId] = Call(from, to, duration);
        emit CallProcessed(msg.sender, callId, ctype, CallProcessorDefenseType.RateLimit);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE & MONITORING
//    • ✅ Defense: SignatureValidation – require admin’s off‐chain approval  
//               Monitoring        – emit audit for each call
////////////////////////////////////////////////////////////////////////////////
contract CallProcessorSafeAdvanced {
    struct Call { address from; address to; uint256 duration; }

    mapping(bytes32 => Call) public calls;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;

    address public signer;
    uint256 public constant MAX_CALLS = 3;

    event CallProcessed(
        address indexed who,
        bytes32           callId,
        CallProcessorType ctype,
        CallProcessorDefenseType defense
    );
    event Audit(
        address indexed who,
        bytes32           callId,
        CallProcessorType ctype,
        CallProcessorDefenseType defense
    );

    error CP__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function processCall(
        bytes32 callId,
        address from,
        address to,
        uint256 duration,
        CallProcessorType ctype,
        bytes calldata sig
    ) external {
        // rate-limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert CP__TooManyRequests();

        // verify signature over (callId||from||to||duration||ctype)
        bytes32 h = keccak256(abi.encodePacked(callId, from, to, duration, ctype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert CP__InvalidSignature();

        calls[callId] = Call(from, to, duration);
        emit CallProcessed(msg.sender, callId, ctype, CallProcessorDefenseType.SignatureValidation);
        emit Audit(msg.sender, callId, ctype, CallProcessorDefenseType.Monitoring);
    }
}
