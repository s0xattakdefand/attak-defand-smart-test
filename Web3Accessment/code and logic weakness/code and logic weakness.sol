// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title CodeLogicWeaknessSuite.sol
/// @notice On‐chain analogues of “Code and Logic Weaknesses” vulnerability patterns:
///   Types: OffByOne, UncheckedReturn, IncorrectCondition, MissingValidation  
///   AttackTypes: LogicBypass, Crash, UnauthorizedAccess, UnexpectedBehavior  
///   DefenseTypes: InputValidation, Assertion, AccessControl, RateLimit, SignatureValidation

enum CLWType              { OffByOne, UncheckedReturn, IncorrectCondition, MissingValidation }
enum CLWAttackType        { LogicBypass, Crash, UnauthorizedAccess, UnexpectedBehavior }
enum CLWDefenseType       { InputValidation, Assertion, AccessControl, RateLimit, SignatureValidation }

error CLW__Unauthorized();
error CLW__InvalidInput();
error CLW__AssertionFailed();
error CLW__TooManyRequests();
error CLW__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE CONTRACT
//    • ❌ no validation: off‐by‐one and unchecked returns → LogicBypass/Crash
////////////////////////////////////////////////////////////////////////////////
contract CLWVuln {
    uint256[] public values;

    event ValuePushed(address indexed who, uint256 value, CLWType dtype, CLWAttackType attack);
    event ValueRemoved(address indexed who, uint256 value, CLWType dtype, CLWAttackType attack);

    function pushValue(uint256 v, CLWType dtype) external {
        // no validation: zero or overflow
        values.push(v);
        emit ValuePushed(msg.sender, v, dtype, CLWAttackType.UnexpectedBehavior);
    }

    function popValue(CLWType dtype) external {
        // unchecked: underflow if empty
        uint256 v = values[values.length - 1];
        values.pop();
        emit ValueRemoved(msg.sender, v, dtype, CLWAttackType.Crash);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates bypass, crash, unauthorized removal
////////////////////////////////////////////////////////////////////////////////
contract Attack_CLW {
    CLWVuln public target;

    constructor(CLWVuln _t) { target = _t; }

    function bypassPush(uint256 v) external {
        // push without business logic
        target.pushValue(v, CLWType.OffByOne);
    }

    function crashPop() external {
        // pop repeatedly to underflow
        target.popValue(CLWType.UncheckedReturn);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may modify
////////////////////////////////////////////////////////////////////////////////
contract CLWSafeAccess {
    uint256[] public values;
    address public owner;

    event ValuePushed(address indexed who, uint256 value, CLWType dtype, CLWDefenseType defense);
    event ValueRemoved(address indexed who, uint256 value, CLWType dtype, CLWDefenseType defense);

    constructor() { owner = msg.sender; }
    modifier onlyOwner() {
        if (msg.sender != owner) revert CLW__Unauthorized();
        _;
    }

    function pushValue(uint256 v, CLWType dtype) external onlyOwner {
        values.push(v);
        emit ValuePushed(msg.sender, v, dtype, CLWDefenseType.AccessControl);
    }

    function popValue(CLWType dtype) external onlyOwner {
        uint256 v = values[values.length - 1];
        values.pop();
        emit ValueRemoved(msg.sender, v, dtype, CLWDefenseType.AccessControl);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH VALIDATION & RATE LIMIT
//    • ✅ Defense: InputValidation – nonzero & bounds  
//               RateLimit        – cap ops per block
////////////////////////////////////////////////////////////////////////////////
contract CLWSafeValidate {
    uint256[] public values;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public opsInBlock;
    uint256 public constant MAX_OPS = 3;

    event ValuePushed(address indexed who, uint256 value, CLWType dtype, CLWDefenseType defense);
    event ValueRemoved(address indexed who, uint256 value, CLWType dtype, CLWDefenseType defense);

    error CLW__TooManyRequests();

    function pushValue(uint256 v, CLWType dtype) external {
        if (v == 0) revert CLW__InvalidInput();
        _rateLimit();
        values.push(v);
        emit ValuePushed(msg.sender, v, dtype, CLWDefenseType.InputValidation);
    }

    function popValue(CLWType dtype) external {
        _rateLimit();
        if (values.length == 0) revert CLW__AssertionFailed();
        uint256 v = values[values.length - 1];
        values.pop();
        emit ValueRemoved(msg.sender, v, dtype, CLWDefenseType.Assertion);
    }

    function _rateLimit() internal {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            opsInBlock[msg.sender] = 0;
        }
        opsInBlock[msg.sender]++;
        if (opsInBlock[msg.sender] > MAX_OPS) revert CLW__TooManyRequests();
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & AUDIT LOGGING
//    • ✅ Defense: SignatureValidation – require admin‐signed ops  
//               AuditLogging       – record each change
////////////////////////////////////////////////////////////////////////////////
contract CLWSafeAdvanced {
    uint256[] public values;
    address public signer;

    event ValuePushed(address indexed who, uint256 value, CLWType dtype, CLWDefenseType defense);
    event ValueRemoved(address indexed who, uint256 value, CLWType dtype, CLWDefenseType defense);
    event AuditLog(address indexed who, string action, uint256 value, CLWDefenseType defense);

    error CLW__InvalidSignature();

    constructor(address _signer) { signer = _signer; }

    function pushValue(
        uint256 v,
        CLWType dtype,
        bytes calldata sig
    ) external {
        // verify signature over (v||dtype||msg.sender)
        bytes32 h = keccak256(abi.encodePacked(msg.sender, v, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v1, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v1, r, s) != signer) revert CLW__InvalidSignature();

        values.push(v);
        emit ValuePushed(msg.sender, v, dtype, CLWDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "pushValue", v, CLWDefenseType.AuditLogging);
    }

    function popValue(
        CLWType dtype,
        bytes calldata sig
    ) external {
        // verify signature over (dtype||msg.sender)
        bytes32 h = keccak256(abi.encodePacked(msg.sender, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v1, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v1, r, s) != signer) revert CLW__InvalidSignature();

        uint256 v = values[values.length - 1];
        values.pop();
        emit ValueRemoved(msg.sender, v, dtype, CLWDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "popValue", v, CLWDefenseType.AuditLogging);
    }
}
