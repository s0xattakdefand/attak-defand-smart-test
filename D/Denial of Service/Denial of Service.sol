// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DenialOfServiceSuite.sol
/// @notice On‑chain analogues of “Denial of Service” (DoS) attack and defense patterns:
///   Types: PacketFlood, HttpFlood, Algorithmic  
///   AttackTypes: Flood, Slowloris, RecursiveCall  
///   DefenseTypes: RateLimit, CircuitBreaker, Authentication  

enum DoSType            { PacketFlood, HttpFlood, Algorithmic }
enum DoSAttackType      { Flood, Slowloris, RecursiveCall }
enum DoSDefenseType     { RateLimit, CircuitBreaker, Authentication }

error DOS__TooManyRequests();
error DOS__CircuitOpen();
error DOS__NotWhitelisted();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE SERVICE (Algorithmic DoS)
///
///    • no limits, expensive per‑call work  
///    • AttackType: RecursiveCall
///─────────────────────────────────────────────────────────────────────────────
contract DoSVuln {
    event Served(address indexed who, DoSType dtype, uint256 work, DoSAttackType attack);

    /// ❌ performs `work` iterations of heavy no‑op each request
    function serve(uint256 work) external {
        for (uint256 i = 0; i < work; i++) {
            // heavy computation stub
        }
        emit Served(msg.sender, DoSType.Algorithmic, work, DoSAttackType.RecursiveCall);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB (Flooding)
///
///    • AttackType: Flood  
///─────────────────────────────────────────────────────────────────────────────
contract Attack_DoS {
    DoSVuln public target;
    constructor(DoSVuln _t) { target = _t; }

    /// flood the vulnerable service
    function flood(uint256 times, uint256 work) external {
        for (uint256 i = 0; i < times; i++) {
            target.serve(work);
        }
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE SERVICE WITH RATE‑LIMITING
///
///    • DefenseType: RateLimit  
///─────────────────────────────────────────────────────────────────────────────
contract DoSRateLimitSafe {
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public countInBlock;
    uint256 public constant MAX_PER_BLOCK = 5;

    event Served(address indexed who, DoSType dtype, uint256 work, DoSDefenseType defense);

    function serve(uint256 work) external {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender]++;
        if (countInBlock[msg.sender] > MAX_PER_BLOCK) revert DOS__TooManyRequests();

        for (uint256 i = 0; i < work; i++) {
            // protected work
        }
        emit Served(msg.sender, DoSType.Algorithmic, work, DoSDefenseType.RateLimit);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE SERVICE WITH CIRCUIT BREAKER
///
///    • DefenseType: CircuitBreaker  
///─────────────────────────────────────────────────────────────────────────────
contract DoSCircuitBreakerSafe {
    uint256 public failureCount;
    bool public circuitOpen;
    uint256 public constant FAILURE_THRESHOLD = 3;
    uint256 public constant RESET_TIMEOUT    = 1 hours;
    uint256 public lastFailureTime;

    event Served(address indexed who, DoSType dtype, uint256 work, DoSDefenseType defense);
    event CircuitTripped(uint256 timestamp);

    modifier closedCircuit() {
        if (circuitOpen && block.timestamp < lastFailureTime + RESET_TIMEOUT) {
            revert DOS__CircuitOpen();
        }
        if (circuitOpen && block.timestamp >= lastFailureTime + RESET_TIMEOUT) {
            // reset circuit
            circuitOpen = false;
            failureCount = 0;
        }
        _;
    }

    function serve(uint256 work) external closedCircuit {
        // simulate failure when work too heavy
        if (work > 1e6) {
            failureCount++;
            lastFailureTime = block.timestamp;
            if (failureCount >= FAILURE_THRESHOLD) {
                circuitOpen = true;
                emit CircuitTripped(block.timestamp);
            }
            return;
        }
        for (uint256 i = 0; i < work; i++) {
            // normal work
        }
        emit Served(msg.sender, DoSType.Algorithmic, work, DoSDefenseType.CircuitBreaker);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 5) SAFE SERVICE WITH AUTHENTICATION
///
///    • DefenseType: Authentication – only whitelisted callers  
///─────────────────────────────────────────────────────────────────────────────
contract DoSAuthSafe {
    mapping(address => bool) public whitelist;
    address public owner;

    event Served(address indexed who, DoSType dtype, uint256 work, DoSDefenseType defense);

    constructor() {
        owner = msg.sender;
    }

    function setWhitelisted(address who, bool ok) external {
        require(msg.sender == owner, "only owner");
        whitelist[who] = ok;
    }

    function serve(uint256 work) external {
        if (!whitelist[msg.sender]) revert DOS__NotWhitelisted();
        for (uint256 i = 0; i < work; i++) {
            // authenticated work
        }
        emit Served(msg.sender, DoSType.Algorithmic, work, DoSDefenseType.Authentication);
    }
}
