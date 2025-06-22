// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title SafeMathValidationSuite.sol
/// @notice Patterns for “Validate Safe Math Libraries to Ensure Proper Calculations”:
///   Types: SafeMathLib, CustomMathLib, FixedPointLib, ManualChecks  
///   AttackTypes: Overflow, Underflow, PrecisionLoss, DivisionByZero  
///   DefenseTypes: BuiltinOverflowCheck, SafeMathLibrary, FixedPoint, ExplicitCheck, SignatureValidation

enum SMVType              { SafeMathLib, CustomMathLib, FixedPointLib, ManualChecks }
enum SMVAttackType        { Overflow, Underflow, PrecisionLoss, DivisionByZero }
enum SMVDefenseType       { BuiltinOverflowCheck, SafeMathLibrary, FixedPoint, ExplicitCheck, SignatureValidation }

error SMV__TooManyRequests();
error SMV__DivisionByZero();
error SMV__PrecisionLoss();
error SMV__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE CALCULATOR
//    • ❌ unchecked: overflows/underflows and truncation allowed
////////////////////////////////////////////////////////////////////////////////
contract SMVVuln {
    event Computed(
        address indexed who,
        SMVType          dtype,
        uint256          a,
        uint256          b,
        uint256          result,
        SMVAttackType    attack
    );

    function add(uint256 a, uint256 b, SMVType dtype) external {
        unchecked {
            uint256 c = a + b;
            emit Computed(msg.sender, dtype, a, b, c, SMVAttackType.Overflow);
        }
    }

    function sub(uint256 a, uint256 b, SMVType dtype) external {
        unchecked {
            uint256 c = a - b;
            emit Computed(msg.sender, dtype, a, b, c, SMVAttackType.Underflow);
        }
    }

    function mul(uint256 a, uint256 b, SMVType dtype) external {
        unchecked {
            uint256 c = a * b;
            emit Computed(msg.sender, dtype, a, b, c, SMVAttackType.PrecisionLoss);
        }
    }

    function div(uint256 a, uint256 b, SMVType dtype) external {
        uint256 c = a / b; // truncates, reverts on zero by EVM
        emit Computed(msg.sender, dtype, a, b, c, SMVAttackType.DivisionByZero);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates overflow, underflow, truncation, division‐by‐zero
////////////////////////////////////////////////////////////////////////////////
contract Attack_SMV {
    SMVVuln public target;
    constructor(SMVVuln _t) { target = _t; }

    function triggerOverflow() external {
        target.add(type(uint256).max, 1, SMVType.SafeMathLib);
    }
    function triggerUnderflow() external {
        target.sub(0, 1, SMVType.SafeMathLib);
    }
    function triggerMulPrecision() external {
        target.mul(type(uint256).max, 2, SMVType.FixedPointLib);
    }
    function triggerDivByZero() external {
        target.div(1, 0, SMVType.CustomMathLib);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH BUILTIN OVERFLOW CHECKS
//    • ✅ Defense: BuiltinOverflowCheck – Solidity ≥0.8 auto‐reverts on overflow/underflow
////////////////////////////////////////////////////////////////////////////////
contract SMVSafeBuiltin {
    event Computed(
        address indexed who,
        SMVType          dtype,
        uint256          a,
        uint256          b,
        uint256          result,
        SMVDefenseType   defense
    );

    function add(uint256 a, uint256 b, SMVType dtype) external {
        uint256 c = a + b;
        emit Computed(msg.sender, dtype, a, b, c, SMVDefenseType.BuiltinOverflowCheck);
    }

    function sub(uint256 a, uint256 b, SMVType dtype) external {
        uint256 c = a - b;
        emit Computed(msg.sender, dtype, a, b, c, SMVDefenseType.BuiltinOverflowCheck);
    }

    function mul(uint256 a, uint256 b, SMVType dtype) external {
        uint256 c = a * b;
        emit Computed(msg.sender, dtype, a, b, c, SMVDefenseType.BuiltinOverflowCheck);
    }

    function div(uint256 a, uint256 b, SMVType dtype) external {
        require(b != 0, "div/zero");
        uint256 c = a / b;
        emit Computed(msg.sender, dtype, a, b, c, SMVDefenseType.BuiltinOverflowCheck);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH EXPLICIT CHECKS & RATE LIMIT
//    • ✅ Defense: ExplicitCheck – guard each op  
//               RateLimit     – cap calls per block
////////////////////////////////////////////////////////////////////////////////
contract SMVSafeValidate {
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MAX_CALLS = 5;

    event Computed(
        address indexed who,
        SMVType          dtype,
        uint256          a,
        uint256          b,
        uint256          result,
        SMVDefenseType   defense
    );
    error SMV__TooManyRequests();

    modifier rateLimit() {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert SMV__TooManyRequests();
        _;
    }

    function add(uint256 a, uint256 b, SMVType dtype) external rateLimit {
        require(a + b >= a, "overflow");
        uint256 c = a + b;
        emit Computed(msg.sender, dtype, a, b, c, SMVDefenseType.ExplicitCheck);
    }

    function sub(uint256 a, uint256 b, SMVType dtype) external rateLimit {
        require(a >= b, "underflow");
        uint256 c = a - b;
        emit Computed(msg.sender, dtype, a, b, c, SMVDefenseType.ExplicitCheck);
    }

    function mul(uint256 a, uint256 b, SMVType dtype) external rateLimit {
        if (a == 0 || b == 0) {
            emit Computed(msg.sender, dtype, a, b, 0, SMVDefenseType.ExplicitCheck);
            return;
        }
        require(a <= type(uint256).max / b, "overflow");
        uint256 c = a * b;
        emit Computed(msg.sender, dtype, a, b, c, SMVDefenseType.ExplicitCheck);
    }

    function div(uint256 a, uint256 b, SMVType dtype) external rateLimit {
        require(b != 0, "div/zero");
        uint256 c = a / b;
        emit Computed(msg.sender, dtype, a, b, c, SMVDefenseType.ExplicitCheck);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & FIXED‐POINT LIB
//    • ✅ Defense: SignatureValidation – require signed params  
//               FixedPoint         – use 1e18 scaling to avoid truncation
////////////////////////////////////////////////////////////////////////////////
library FixedPointMath {
    uint256 internal constant SCALE = 1e18;
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        return (a * b) / SCALE;
    }
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        return (a * SCALE) / b;
    }
}

contract SMVSafeAdvanced {
    address public signer;

    event Computed(
        address indexed who,
        SMVType          dtype,
        uint256          a,
        uint256          b,
        uint256          result,
        SMVDefenseType   defense
    );
    event AuditLog(
        address indexed who,
        SMVType          dtype,
        uint256          a,
        uint256          b,
        uint256          result,
        SMVDefenseType   defense
    );
    error SMV__InvalidSignature();
    error SMV__DivisionByZero();

    constructor(address _signer) {
        signer = _signer;
    }

    function add(
        uint256 a,
        uint256 b,
        SMVType dtype,
        bytes calldata sig
    ) external {
        // verify signature over inputs
        bytes32 h = keccak256(abi.encodePacked(a, b, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert SMV__InvalidSignature();

        uint256 c = a + b; // builtin check
        emit Computed(msg.sender, dtype, a, b, c, SMVDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, dtype, a, b, c, SMVDefenseType.AuditLogging);
    }

    function mul(
        uint256 a,
        uint256 b,
        SMVType dtype,
        bytes calldata sig
    ) external {
        // verify signature
        bytes32 h = keccak256(abi.encodePacked(a, b, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert SMV__InvalidSignature();

        // fixed‐point multiply
        uint256 result = FixedPointMath.mul(a, b);
        emit Computed(msg.sender, dtype, a, b, result, SMVDefenseType.FixedPoint);
        emit AuditLog(msg.sender, dtype, a, b, result, SMVDefenseType.AuditLogging);
    }

    function div(
        uint256 a,
        uint256 b,
        SMVType dtype,
        bytes calldata sig
    ) external {
        // verify signature
        bytes32 h = keccak256(abi.encodePacked(a, b, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert SMV__InvalidSignature();

        if (b == 0) revert SMV__DivisionByZero();
        uint256 result = FixedPointMath.div(a, b);
        emit Computed(msg.sender, dtype, a, b, result, SMVDefenseType.FixedPoint);
        emit AuditLog(msg.sender, dtype, a, b, result, SMVDefenseType.AuditLogging);
    }
}
