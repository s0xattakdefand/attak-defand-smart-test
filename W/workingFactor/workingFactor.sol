// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title WorkingFactorSuite.sol
/// @notice On‐chain analogues of “Working Factor” configuration patterns:
///   Types: Static, TimeBased, Iteration, Adaptive  
///   AttackTypes: BruteForce, DictionaryAttack, Replay, TimingAttack  
///   DefenseTypes: AccessControl, RangeValidation, RateLimit, SignatureValidation

enum WorkingFactorType         { Static, TimeBased, Iteration, Adaptive }
enum WFAttackType              { BruteForce, DictionaryAttack, Replay, TimingAttack }
enum WFDefenseType             { AccessControl, RangeValidation, RateLimit, SignatureValidation }

error WF__NotOwner();
error WF__InvalidFactor();
error WF__TooManyRequests();
error WF__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE CONFIGURATION
//    • ❌ no checks: anyone may set any factor → DictionaryAttack
////////////////////////////////////////////////////////////////////////////////
contract WorkingFactorVuln {
    mapping(address => uint256) public factor;
    event FactorSet(
        address indexed who,
        uint256          value,
        WorkingFactorType ftype,
        WFAttackType     attack
    );

    function setFactor(uint256 value, WorkingFactorType ftype) external {
        factor[msg.sender] = value;
        emit FactorSet(msg.sender, value, ftype, WFAttackType.DictionaryAttack);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates brute‐force and replay of factor settings
////////////////////////////////////////////////////////////////////////////////
contract Attack_WorkingFactor {
    WorkingFactorVuln public target;
    uint256 public lastValue;
    WorkingFactorType public lastType;

    constructor(WorkingFactorVuln _t) { target = _t; }

    function capture(uint256 value, WorkingFactorType ftype) external {
        lastValue = value;
        lastType = ftype;
    }

    function bruteForce(uint256 start, uint256 end, WorkingFactorType ftype) external {
        for (uint256 v = start; v <= end; v++) {
            target.setFactor(v, ftype);
        }
    }

    function replay() external {
        target.setFactor(lastValue, lastType);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may set factor
////////////////////////////////////////////////////////////////////////////////
contract WorkingFactorSafeAccess {
    mapping(address => uint256) public factor;
    address public owner;

    event FactorSet(
        address indexed who,
        uint256          value,
        WorkingFactorType ftype,
        WFDefenseType    defense
    );

    constructor() {
        owner = msg.sender;
    }

    function setFactor(uint256 value, WorkingFactorType ftype) external {
        if (msg.sender != owner) revert WF__NotOwner();
        factor[msg.sender] = value;
        emit FactorSet(msg.sender, value, ftype, WFDefenseType.AccessControl);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH RANGE VALIDATION & RATE LIMIT
//    • ✅ Defense: RangeValidation – enforce min/max  
//               RateLimit – cap changes per block
////////////////////////////////////////////////////////////////////////////////
contract WorkingFactorSafeValidation {
    mapping(address => uint256) public factor;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public changesInBlock;
    uint256 public constant MIN_FACTOR = 1;
    uint256 public constant MAX_FACTOR = 1e6;
    uint256 public constant MAX_CHANGES = 3;

    event FactorSet(
        address indexed who,
        uint256          value,
        WorkingFactorType ftype,
        WFDefenseType    defense
    );

    error WF__TooManyRequests();

    function setFactor(uint256 value, WorkingFactorType ftype) external {
        // rate-limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            changesInBlock[msg.sender] = 0;
        }
        changesInBlock[msg.sender]++;
        if (changesInBlock[msg.sender] > MAX_CHANGES) revert WF__TooManyRequests();

        // range check
        if (value < MIN_FACTOR || value > MAX_FACTOR) revert WF__InvalidFactor();

        factor[msg.sender] = value;
        emit FactorSet(msg.sender, value, ftype, WFDefenseType.RangeValidation);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & RATE LIMIT
//    • ✅ Defense: SignatureValidation – require admin signature  
//               RateLimit – cap signed updates per block
////////////////////////////////////////////////////////////////////////////////
contract WorkingFactorSafeAdvanced {
    mapping(address => uint256) public factor;
    address public signer;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public updatesInBlock;
    uint256 public constant MAX_UPDATES = 5;

    event FactorSet(
        address indexed who,
        uint256          value,
        WorkingFactorType ftype,
        WFDefenseType    defense
    );

    error WF__TooManyRequests();
    error WF__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function setFactor(
        uint256 value,
        WorkingFactorType ftype,
        bytes calldata sig
    ) external {
        // rate-limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            updatesInBlock[msg.sender] = 0;
        }
        updatesInBlock[msg.sender]++;
        if (updatesInBlock[msg.sender] > MAX_UPDATES) revert WF__TooManyRequests();

        // verify signature over (msg.sender||value||ftype)
        bytes32 h = keccak256(abi.encodePacked(msg.sender, value, ftype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert WF__InvalidSignature();

        factor[msg.sender] = value;
        emit FactorSet(msg.sender, value, ftype, WFDefenseType.SignatureValidation);
    }
}
