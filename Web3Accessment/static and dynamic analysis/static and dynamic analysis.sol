// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title StatusAndDynamicAnalysisSuite.sol
/// @notice On‐chain analogues of “Status and Dynamic Analysis” patterns:
///   Types: StatusCheck, DynamicAnalysis, FuzzTesting, RuntimeMonitoring  
///   AttackTypes: EvasiveBehavior, Tampering, TimingAttack, MemoryLeak  
///   DefenseTypes: StatusCheck, InvariantEnforcement, FuzzGuard, Monitoring, SignatureValidation

enum SDType                { StatusCheck, DynamicAnalysis, FuzzTesting, RuntimeMonitoring }
enum SDAttackType          { EvasiveBehavior, Tampering, TimingAttack, MemoryLeak }
enum SDDefenseType         { StatusCheck, InvariantEnforcement, FuzzGuard, Monitoring, SignatureValidation }

error SDA__InvariantViolated();
error SDA__TooManyRequests();
error SDA__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE ANALYZER
//    • ❌ no checks: anyone may flip flags or bypass → EvasiveBehavior, Tampering
////////////////////////////////////////////////////////////////////////////////
contract SDAVuln {
    bool public ready;
    uint256 public lastRun;

    event FlagSet(address indexed who, bool ready, SDType dtype, SDAttackType attack);
    event AnalysisRun(address indexed who, uint256 timestamp, SDType dtype, SDAttackType attack);

    function setReady(bool _ready, SDType dtype) external {
        ready = _ready;
        emit FlagSet(msg.sender, _ready, dtype, SDAttackType.Tampering);
    }

    function runAnalysis(SDType dtype) external {
        lastRun = block.timestamp;
        emit AnalysisRun(msg.sender, lastRun, dtype, SDAttackType.EvasiveBehavior);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates evasive behavior, tampering, timing attacks, memory leaks
////////////////////////////////////////////////////////////////////////////////
contract Attack_SDA {
    SDAVuln public target;
    bool public lastReady;

    constructor(SDAVuln _t) {
        target = _t;
    }

    function spoofFlag(bool v) external {
        target.setReady(v, SDType.StatusCheck);
        lastReady = v;
    }

    function timingAttack() external {
        // call at two different blocks
        target.runAnalysis(SDType.DynamicAnalysis);
        target.runAnalysis(SDType.DynamicAnalysis);
    }

    function replayFlag() external {
        target.setReady(lastReady, SDType.StatusCheck);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH STATUS CHECK
//    • ✅ Defense: StatusCheck – require ready flag before run
////////////////////////////////////////////////////////////////////////////////
contract SDASafeStatus {
    bool public ready;
    uint256 public lastRun;

    event FlagSet(address indexed who, bool ready, SDType dtype, SDDefenseType defense);
    event AnalysisRun(address indexed who, uint256 timestamp, SDType dtype, SDDefenseType defense);

    function setReady(bool _ready, SDType dtype) external {
        ready = _ready;
        emit FlagSet(msg.sender, _ready, dtype, SDDefenseType.StatusCheck);
    }

    function runAnalysis(SDType dtype) external {
        require(ready, "not ready");
        lastRun = block.timestamp;
        emit AnalysisRun(msg.sender, lastRun, dtype, SDDefenseType.StatusCheck);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH INVARIANT ENFORCEMENT & RATE LIMIT
//    • ✅ Defense: InvariantEnforcement – check monotonic timestamp  
//               RateLimit            – cap runs per block
////////////////////////////////////////////////////////////////////////////////
contract SDASafeValidate {
    bool public ready;
    uint256 public lastRun;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public runsInBlock;
    uint256 public constant MAX_RUNS = 3;

    event FlagSet(address indexed who, bool ready, SDType dtype, SDDefenseType defense);
    event AnalysisRun(address indexed who, uint256 timestamp, SDType dtype, SDDefenseType defense);

    function setReady(bool _ready, SDType dtype) external {
        ready = _ready;
        emit FlagSet(msg.sender, _ready, dtype, SDDefenseType.InvariantEnforcement);
    }

    function runAnalysis(SDType dtype) external {
        require(ready, "not ready");
        // invariant: timestamp must increase
        require(block.timestamp > lastRun, "timestamp invariant");
        // rate-limit per block
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender] = block.number;
            runsInBlock[msg.sender] = 0;
        }
        runsInBlock[msg.sender]++;
        if (runsInBlock[msg.sender] > MAX_RUNS) revert SDA__TooManyRequests();

        lastRun = block.timestamp;
        emit AnalysisRun(msg.sender, lastRun, dtype, SDDefenseType.InvariantEnforcement);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH FUZZ GUARD, MONITORING & SIGNATURE VALIDATION
//    • ✅ Defense: FuzzGuard           – stub for dynamic input checks  
//               Monitoring           – emit always  
//               SignatureValidation  – require admin approval
////////////////////////////////////////////////////////////////////////////////
contract SDASafeAdvanced {
    bool public ready;
    uint256 public lastRun;
    address public signer;

    event FlagSet(address indexed who, bool ready, SDType dtype, SDDefenseType defense);
    event AnalysisRun(address indexed who, uint256 timestamp, SDType dtype, SDDefenseType defense);
    event Alert(address indexed who, string message, SDDefenseType defense);

    error SDA__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function setReady(
        bool _ready,
        SDType dtype,
        bytes calldata sig
    ) external {
        // signature over (_ready||dtype)
        bytes32 h = keccak256(abi.encodePacked(_ready, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert SDA__InvalidSignature();

        ready = _ready;
        emit FlagSet(msg.sender, _ready, dtype, SDDefenseType.FuzzGuard);
        emit Alert(msg.sender, "flag changed", SDDefenseType.Monitoring);
    }

    function runAnalysis(
        SDType dtype,
        bytes calldata /*fuzzInput stub*/
    ) external {
        require(ready, "not ready");
        // stub for dynamic/fuzz checks
        lastRun = block.timestamp;
        emit AnalysisRun(msg.sender, lastRun, dtype, SDDefenseType.Monitoring);
    }
}
