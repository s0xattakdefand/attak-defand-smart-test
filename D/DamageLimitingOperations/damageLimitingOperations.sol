// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DamageLimitingOperationsSuite.sol
/// @notice On‐chain analogues of “Damage Limiting Operations” patterns:
///   Types: EmergencyShutdown, CircuitBreaker, Throttling, Quarantine  
///   AttackTypes: Overload, SpoofCommand, BypassLimit, DenialOfService  
///   DefenseTypes: AccessControl, ParameterChecks, RateLimit, CircuitBreaker, SignatureValidation

enum DamageLimitingType       { EmergencyShutdown, CircuitBreaker, Throttling, Quarantine }
enum DamageAttackType         { Overload, SpoofCommand, BypassLimit, DenialOfService }
enum DamageDefenseType        { AccessControl, ParameterChecks, RateLimit, CircuitBreaker, SignatureValidation }

error DLO__NotOwner();
error DLO__InvalidParams();
error DLO__CircuitOpen();
error DLO__TooManyRequests();
error DLO__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE DAMAGE LIMITER
//    • ❌ no checks: anyone may trigger any operation → Overload / SpoofCommand
////////////////////////////////////////////////////////////////////////////////
contract DamageLimitingVuln {
    bool public emergencyActive;
    mapping(address => uint256) public usage;

    event Operation(
        address indexed who,
        DamageLimitingType dtype,
        DamageAttackType  attack
    );

    function triggerEmergency() external {
        emergencyActive = true;
        emit Operation(msg.sender, DamageLimitingType.EmergencyShutdown, DamageAttackType.SpoofCommand);
    }

    function performAction(uint256 amount) external {
        usage[msg.sender] += amount;
        emit Operation(msg.sender, DamageLimitingType.Throttling, DamageAttackType.Overload);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates overload, command spoof, bypass, DoS
////////////////////////////////////////////////////////////////////////////////
contract Attack_DamageLimiter {
    DamageLimitingVuln public target;

    constructor(DamageLimitingVuln _t) {
        target = _t;
    }

    function spoofShutdown() external {
        target.triggerEmergency();
    }

    function flood(uint256 amount, uint count) external {
        for (uint i = 0; i < count; i++) {
            target.performAction(amount);
        }
    }

    function bypass() external {
        // bypass any future checks
        target.performAction(type(uint256).max);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may trigger emergency
////////////////////////////////////////////////////////////////////////////////
contract DamageLimitingSafeAccess {
    bool public emergencyActive;
    mapping(address => uint256) public usage;
    address public owner;

    event Operation(
        address indexed who,
        DamageLimitingType dtype,
        DamageDefenseType defense
    );

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert DLO__NotOwner();
        _;
    }

    function triggerEmergency() external onlyOwner {
        emergencyActive = true;
        emit Operation(msg.sender, DamageLimitingType.EmergencyShutdown, DamageDefenseType.AccessControl);
    }

    function performAction(uint256 amount) external {
        usage[msg.sender] += amount;
        emit Operation(msg.sender, DamageLimitingType.Throttling, DamageDefenseType.AccessControl);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH PARAMETER CHECKS, RATE LIMIT & CIRCUIT BREAKER
//    • ✅ Defense: ParameterChecks – amount > 0 & ≤ maxPerCall  
//               RateLimit       – cap calls per block  
//               CircuitBreaker  – block actions when emergencyActive
////////////////////////////////////////////////////////////////////////////////
contract DamageLimitingSafeValidate {
    bool public emergencyActive;
    mapping(address => uint256) public usage;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MAX_PER_CALL = 100;
    uint256 public constant MAX_CALLS_PER_BLOCK = 3;

    event Operation(
        address indexed who,
        DamageLimitingType dtype,
        DamageDefenseType defense
    );

    error DLO__InvalidParams();
    error DLO__TooManyRequests();
    error DLO__CircuitOpen();

    function triggerEmergency() external {
        emergencyActive = true;
        emit Operation(msg.sender, DamageLimitingType.EmergencyShutdown, DamageDefenseType.CircuitBreaker);
    }

    function performAction(uint256 amount) external {
        if (emergencyActive) revert DLO__CircuitOpen();
        if (amount == 0 || amount > MAX_PER_CALL) revert DLO__InvalidParams();

        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS_PER_BLOCK) revert DLO__TooManyRequests();

        usage[msg.sender] += amount;
        emit Operation(msg.sender, DamageLimitingType.Throttling, DamageDefenseType.RateLimit);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & AUDIT LOGGING
//    • ✅ Defense: SignatureValidation – require admin signature for shutdown  
//               AuditLogging         – log every operation
////////////////////////////////////////////////////////////////////////////////
contract DamageLimitingSafeAdvanced {
    bool public emergencyActive;
    mapping(address => uint256) public usage;
    address public signer;

    event Operation(
        address indexed who,
        DamageLimitingType dtype,
        DamageDefenseType defense
    );
    event AuditLog(
        address indexed who,
        DamageLimitingType dtype,
        DamageDefenseType defense
    );

    error DLO__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function triggerEmergency(bytes calldata sig) external {
        // verify signature over "EMERGENCY"
        bytes32 h = keccak256(abi.encodePacked("EMERGENCY"));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DLO__InvalidSignature();

        emergencyActive = true;
        emit Operation(msg.sender, DamageLimitingType.EmergencyShutdown, DamageDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, DamageLimitingType.EmergencyShutdown, DamageDefenseType.AuditLogging);
    }

    function performAction(uint256 amount) external {
        if (emergencyActive) revert DLO__CircuitOpen();

        usage[msg.sender] += amount;
        emit Operation(msg.sender, DamageLimitingType.Throttling, DamageDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, DamageLimitingType.Throttling, DamageDefenseType.AuditLogging);
    }
}
