// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title EdgeCaseOverflowUnderflowSuite.sol
/// @notice Patterns for “Inject edge case inputs to check for overflows and underflow”:
///   Types: MinMax, Zero, One, MaxMinusOne, Random  
///   AttackTypes: ForcedOverflow, ForcedUnderflow  
///   DefenseTypes: BuiltinOverflowCheck, ExplicitCheck, RateLimit, SignatureValidation, FuzzGuard

enum InputTestType    { MinMax, Zero, One, MaxMinusOne, Random }
enum EdgeAttackType   { ForcedOverflow, ForcedUnderflow }
enum EdgeDefenseType  { BuiltinOverflowCheck, ExplicitCheck, RateLimit, SignatureValidation, FuzzGuard }

error EC__TooManyRequests();
error EC__InvalidSignature();
error EC__DivisionByZero();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE CONTRACT
//    • ❌ unchecked: overflows/underflows allowed on edge inputs
////////////////////////////////////////////////////////////////////////////////
contract ECVuln {
    event Tested(
        address indexed who,
        InputTestType    ttype,
        uint256          a,
        uint256          b,
        uint256          result,
        EdgeAttackType   attack
    );

    function testAdd(uint256 a, uint256 b, InputTestType ttype) external {
        unchecked {
            uint256 c = a + b;
            emit Tested(msg.sender, ttype, a, b, c, EdgeAttackType.ForcedOverflow);
        }
    }

    function testSub(uint256 a, uint256 b, InputTestType ttype) external {
        unchecked {
            uint256 c = a - b;
            emit Tested(msg.sender, ttype, a, b, c, EdgeAttackType.ForcedUnderflow);
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates injection of edge values to overflow/underflow
////////////////////////////////////////////////////////////////////////////////
contract Attack_EC {
    ECVuln public target;

    constructor(ECVuln _t) { target = _t; }

    function overflowMax() external {
        // max + 1
        target.testAdd(type(uint256).max, 1, InputTestType.MinMax);
    }
    function underflowZero() external {
        // 0 - 1
        target.testSub(0, 1, InputTestType.Zero);
    }
    function boundaryMaxMinusOne() external {
        target.testAdd(type(uint256).max - 1, 2, InputTestType.MaxMinusOne);
    }
    function randomCase(uint256 a, uint256 b) external {
        target.testAdd(a, b, InputTestType.Random);
        target.testSub(a, b, InputTestType.Random);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH BUILTIN OVERFLOW CHECKS
//    • ✅ Defense: BuiltinOverflowCheck – Solidity ≥0.8 auto‐reverts
////////////////////////////////////////////////////////////////////////////////
contract ECSafeBuiltin {
    event Tested(
        address indexed who,
        InputTestType    ttype,
        uint256          a,
        uint256          b,
        uint256          result,
        EdgeDefenseType  defense
    );

    function testAdd(uint256 a, uint256 b, InputTestType ttype) external {
        uint256 c = a + b; // reverts on overflow
        emit Tested(msg.sender, ttype, a, b, c, EdgeDefenseType.BuiltinOverflowCheck);
    }

    function testSub(uint256 a, uint256 b, InputTestType ttype) external {
        uint256 c = a - b; // reverts on underflow
        emit Tested(msg.sender, ttype, a, b, c, EdgeDefenseType.BuiltinOverflowCheck);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH EXPLICIT CHECKS & RATE LIMIT
//    • ✅ Defense: ExplicitCheck – guard each op  
//               RateLimit     – cap tests per block
////////////////////////////////////////////////////////////////////////////////
contract ECSafeValidate {
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MAX_CALLS = 5;

    event Tested(
        address indexed who,
        InputTestType    ttype,
        uint256          a,
        uint256          b,
        uint256          result,
        EdgeDefenseType  defense
    );

    error EC__TooManyRequests();
    error EC__PrecisionLoss();

    modifier rateLimit() {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert EC__TooManyRequests();
        _;
    }

    function testAdd(uint256 a, uint256 b, InputTestType ttype) external rateLimit {
        require(a + b >= a, "overflow");
        uint256 c = a + b;
        emit Tested(msg.sender, ttype, a, b, c, EdgeDefenseType.ExplicitCheck);
    }

    function testSub(uint256 a, uint256 b, InputTestType ttype) external rateLimit {
        require(a >= b, "underflow");
        uint256 c = a - b;
        emit Tested(msg.sender, ttype, a, b, c, EdgeDefenseType.ExplicitCheck);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & FUZZ GUARD
//    • ✅ Defense: SignatureValidation – require signed params  
//               FuzzGuard         – stub for fuzz‐based input checks
////////////////////////////////////////////////////////////////////////////////
contract ECSafeAdvanced {
    address public signer;

    event Tested(
        address indexed who,
        InputTestType    ttype,
        uint256          a,
        uint256          b,
        uint256          result,
        EdgeDefenseType  defense
    );
    event AuditLog(
        address indexed who,
        InputTestType    ttype,
        uint256          a,
        uint256          b,
        uint256          result,
        EdgeDefenseType  defense
    );

    error EC__InvalidSignature();
    error EC__PrecisionLoss();

    constructor(address _signer) {
        signer = _signer;
    }

    function testAdd(
        uint256 a,
        uint256 b,
        InputTestType ttype,
        bytes calldata sig
    ) external {
        // verify signature over (a||b||ttype)
        bytes32 h = keccak256(abi.encodePacked(a, b, ttype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert EC__InvalidSignature();

        // fuzz guard stub: could integrate fuzz tests off‐chain
        uint256 c = a + b; // relies on builtin check
        emit Tested(msg.sender, ttype, a, b, c, EdgeDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, ttype, a, b, c, EdgeDefenseType.FuzzGuard);
    }

    function testSub(
        uint256 a,
        uint256 b,
        InputTestType ttype,
        bytes calldata sig
    ) external {
        // verify signature
        bytes32 h = keccak256(abi.encodePacked(a, b, ttype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert EC__InvalidSignature();

        require(a >= b, "underflow");
        uint256 c = a - b;
        emit Tested(msg.sender, ttype, a, b, c, EdgeDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, ttype, a, b, c, EdgeDefenseType.FuzzGuard);
    }
}
