// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title NumericErrorPreventionSuite.sol
/// @notice Patterns to “Prevent unexpected numerical error from breaking your contract”:
///   Types: PrecisionLoss, RoundingError, DivisionTruncation, Overflow, Underflow  
///   AttackTypes: PrecisionAbuse, TruncationAttack, RoundingManipulation, ArithmeticOverflow, ArithmeticUnderflow  
///   DefenseTypes: SafeMath, FixedPoint, ExplicitCheck, RateLimit, SignatureValidation

enum PNType                { PrecisionLoss, RoundingError, DivisionTruncation, Overflow, Underflow }
enum PNAttackType          { PrecisionAbuse, TruncationAttack, RoundingManipulation, ArithmeticOverflow, ArithmeticUnderflow }
enum PNDefenseType         { SafeMath, FixedPoint, ExplicitCheck, RateLimit, SignatureValidation }

error PN__TooManyRequests();
error PN__DivisionByZero();
error PN__InvalidSignature();
error PN__PrecisionLoss();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE CALCULATOR
//    • ❌ no protections: fractional results truncated → PrecisionLoss, RoundingError
////////////////////////////////////////////////////////////////////////////////
contract PNVuln {
    event Computed(
        address indexed who,
        uint256          numerator,
        uint256          denominator,
        uint256          result,
        PNType           dtype,
        PNAttackType     attack
    );

    function computeFraction(uint256 numerator, uint256 denominator, PNType dtype) external {
        // truncates fractional part
        uint256 result = numerator / denominator;
        emit Computed(msg.sender, numerator, denominator, result, dtype, PNAttackType.TruncationAttack);
    }

    function multiply(uint256 a, uint256 b, PNType dtype) external {
        unchecked {
            uint256 product = a * b;
            emit Computed(msg.sender, a, b, product, dtype, PNAttackType.ArithmeticOverflow);
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates precision abuse, truncation, overflow, underflow
////////////////////////////////////////////////////////////////////////////////
contract Attack_PN {
    PNVuln public target;

    constructor(PNVuln _t) { target = _t; }

    function abusePrecision(uint256 n, uint256 d) external {
        // cause large truncation
        target.computeFraction(n, d, PNType.DivisionTruncation);
    }

    function overflowMul(uint256 a, uint256 b) external {
        // cause overflow
        target.multiply(type(uint256).max, 2, PNType.Overflow);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH BUILTIN SAFE MATH
//    • ✅ Defense: SafeMath – Solidity ≥0.8 checks overflow/underflow
////////////////////////////////////////////////////////////////////////////////
contract PNSafeBuiltin {
    event Computed(
        address indexed who,
        uint256          numerator,
        uint256          denominator,
        uint256          result,
        PNType           dtype,
        PNDefenseType    defense
    );

    function computeFraction(uint256 numerator, uint256 denominator, PNType dtype) external {
        require(denominator != 0, "div/zero");
        uint256 result = numerator / denominator;
        emit Computed(msg.sender, numerator, denominator, result, dtype, PNDefenseType.SafeMath);
    }

    function multiply(uint256 a, uint256 b, PNType dtype) external {
        uint256 product = a * b; // reverts on overflow
        emit Computed(msg.sender, a, b, product, dtype, PNDefenseType.SafeMath);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH EXPLICIT CHECKS & RATE LIMIT
//    • ✅ Defense: ExplicitCheck – guard division/truncation  
//               RateLimit     – cap calls per block
////////////////////////////////////////////////////////////////////////////////
contract PNSafeValidate {
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MAX_CALLS = 5;

    event Computed(
        address indexed who,
        uint256          numerator,
        uint256          denominator,
        uint256          result,
        PNType           dtype,
        PNDefenseType    defense
    );

    error PN__TooManyRequests();
    error PN__DivisionByZero();

    modifier rateLimit() {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert PN__TooManyRequests();
        _;
    }

    function computeFraction(uint256 numerator, uint256 denominator, PNType dtype) external rateLimit {
        if (denominator == 0) revert PN__DivisionByZero();
        // explicit check for precision loss: require minimal precision
        uint256 result = numerator / denominator;
        if (numerator % denominator != 0) revert PN__PrecisionLoss();
        emit Computed(msg.sender, numerator, denominator, result, dtype, PNDefenseType.ExplicitCheck);
    }

    function multiply(uint256 a, uint256 b, PNType dtype) external rateLimit {
        unchecked {
            uint256 product = a * b;
            require(a == 0 || product / a == b, "overflow");
            emit Computed(msg.sender, a, b, product, dtype, PNDefenseType.ExplicitCheck);
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & FIXED‐POINT
//    • ✅ Defense: SignatureValidation – require signed params  
//               FixedPoint         – use 1e18 scaling to avoid truncation
////////////////////////////////////////////////////////////////////////////////
contract PNSafeAdvanced {
    address public signer;

    event Computed(
        address indexed who,
        uint256          numerator,
        uint256          denominator,
        uint256          result,
        PNType           dtype,
        PNDefenseType    defense
    );

    error PN__InvalidSignature();
    error PN__DivisionByZero();

    constructor(address _signer) {
        signer = _signer;
    }

    function computeFraction(
        uint256 numerator,
        uint256 denominator,
        PNType dtype,
        bytes calldata sig
    ) external {
        // verify signature over inputs
        bytes32 h = keccak256(abi.encodePacked(numerator, denominator, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert PN__InvalidSignature();

        if (denominator == 0) revert PN__DivisionByZero();
        // fixed‐point calculation with 1e18 scale
        uint256 result = (numerator * 1e18) / denominator;
        emit Computed(msg.sender, numerator, denominator, result, dtype, PNDefenseType.FixedPoint);
    }

    function multiply(
        uint256 a,
        uint256 b,
        PNType dtype,
        bytes calldata sig
    ) external {
        // verify signature
        bytes32 h = keccak256(abi.encodePacked(a, b, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert PN__InvalidSignature();

        // fixed‐point multiply: (a * b) / 1e18
        uint256 product = a * b;
        require(a == 0 || product / a == b, "overflow");
        uint256 result = product / 1e18;
        emit Computed(msg.sender, a, b, result, dtype, PNDefenseType.FixedPoint);
    }
}
