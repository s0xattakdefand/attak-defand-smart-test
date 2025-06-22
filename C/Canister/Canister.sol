// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title CanisterSuite.sol
/// @notice On‐chain analogues of “Canister” (smart container) patterns:
///   Types: System, Application, Management, Wallet  
///   AttackTypes: CycleDrain, CodeInjection, DenialOfService, AccessBypass  
///   DefenseTypes: AccessControl, RateLimit, CodeValidation, Monitoring

enum CanisterType           { System, Application, Management, Wallet }
enum CanisterAttackType     { CycleDrain, CodeInjection, DenialOfService, AccessBypass }
enum CanisterDefenseType    { AccessControl, RateLimit, CodeValidation, Monitoring }

error CAN__NotAuthorized();
error CAN__TooManyRequests();
error CAN__InvalidCode();
error CAN__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE CANISTER CONTROLLER
//    • ❌ no checks: anyone may invoke arbitrary canister payloads → AccessBypass
////////////////////////////////////////////////////////////////////////////////
contract CanisterVuln {
    mapping(uint256 => bytes) public storage;
    event CanisterInvoked(
        address indexed who,
        uint256          canisterId,
        CanisterType     ctype,
        bytes            payload,
        CanisterAttackType attack
    );

    function invoke(
        uint256 canisterId,
        CanisterType ctype,
        bytes calldata payload
    ) external {
        // naïve: store last payload
        storage[canisterId] = payload;
        emit CanisterInvoked(msg.sender, canisterId, ctype, payload, CanisterAttackType.AccessBypass);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates cycle drain, code injection, replay, DoS
////////////////////////////////////////////////////////////////////////////////
contract Attack_Canister {
    CanisterVuln public target;
    uint256 public lastCanister;
    bytes   public lastPayload;

    constructor(CanisterVuln _t) { target = _t; }

    function drainCycles(uint256 canisterId, bytes calldata payload) external {
        // attacker spams invocation to drain cycles
        for (uint i = 0; i < 3; i++) {
            target.invoke(canisterId, CanisterType.Application, payload);
        }
    }

    function injectCode(uint256 canisterId, bytes calldata payload) external {
        // attacker writes malicious payload
        target.invoke(canisterId, CanisterType.Management, payload);
        lastCanister = canisterId;
        lastPayload = payload;
    }

    function replay() external {
        target.invoke(lastCanister, CanisterType.Management, lastPayload);
    }

    function dos(uint256 canisterId) external {
        // flood with empty payloads
        drainCycles(canisterId, "");
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may invoke
////////////////////////////////////////////////////////////////////////////////
contract CanisterSafeAccess {
    mapping(uint256 => bytes) public storage;
    address public owner;

    event CanisterInvoked(
        address indexed who,
        uint256          canisterId,
        CanisterType     ctype,
        bytes            payload,
        CanisterDefenseType defense
    );

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert CAN__NotAuthorized();
        _;
    }

    function invoke(
        uint256 canisterId,
        CanisterType ctype,
        bytes calldata payload
    ) external onlyOwner {
        storage[canisterId] = payload;
        emit CanisterInvoked(msg.sender, canisterId, ctype, payload, CanisterDefenseType.AccessControl);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH RATE LIMIT
//    • ✅ Defense: RateLimit – cap invocations per block per caller
////////////////////////////////////////////////////////////////////////////////
contract CanisterSafeRateLimit {
    mapping(uint256 => bytes) public storage;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MAX_CALLS = 5;

    event CanisterInvoked(
        address indexed who,
        uint256          canisterId,
        CanisterType     ctype,
        bytes            payload,
        CanisterDefenseType defense
    );

    error CAN__TooManyRequests();

    function invoke(
        uint256 canisterId,
        CanisterType ctype,
        bytes calldata payload
    ) external {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender] = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert CAN__TooManyRequests();

        storage[canisterId] = payload;
        emit CanisterInvoked(msg.sender, canisterId, ctype, payload, CanisterDefenseType.RateLimit);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH CODE VALIDATION & MONITORING
//    • ✅ Defense: CodeValidation – require off-chain signed code payload  
//               Monitoring     – emit audit for every invoke
////////////////////////////////////////////////////////////////////////////////
contract CanisterSafeAdvanced {
    mapping(uint256 => bytes) public storage;
    address public signer;

    event CanisterInvoked(
        address indexed who,
        uint256          canisterId,
        CanisterType     ctype,
        bytes            payload,
        CanisterDefenseType defense
    );
    event AuditLog(
        address indexed who,
        uint256          canisterId,
        CanisterType     ctype,
        bytes            payload,
        CanisterDefenseType defense
    );

    error CAN__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function invoke(
        uint256 canisterId,
        CanisterType ctype,
        bytes calldata payload,
        bytes calldata sig
    ) external {
        // verify signature over (canisterId||ctype||payload)
        bytes32 h = keccak256(abi.encodePacked(canisterId, ctype, payload));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert CAN__InvalidSignature();

        storage[canisterId] = payload;
        emit CanisterInvoked(msg.sender, canisterId, ctype, payload, CanisterDefenseType.CodeValidation);
        emit AuditLog(msg.sender, canisterId, ctype, payload, CanisterDefenseType.Monitoring);
    }
}
