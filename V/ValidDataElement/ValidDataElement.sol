// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title ValidDataElementSuite.sol
/// @notice On-chain analogues of “Valid Data Element” validation patterns:
///   Types: FormatCheck, SchemaCheck, RangeCheck, TypeCheck  
///   AttackTypes: MalformedInput, Injection, Overflow, MissingField  
///   DefenseTypes: InputValidation, SchemaValidation, RangeValidation, TypeEnforcement  

enum ValidDataElementType        { FormatCheck, SchemaCheck, RangeCheck, TypeCheck }
enum ValidDataElementAttackType  { MalformedInput, Injection, Overflow, MissingField }
enum ValidDataElementDefenseType { InputValidation, SchemaValidation, RangeValidation, TypeEnforcement }

error VDE__InvalidInput();
error VDE__NotAllowed();
error VDE__OutOfRange();
error VDE__TypeMismatch();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE STORE (no validation)
//    • anyone may write any value → MalformedInput, Overflow
////////////////////////////////////////////////////////////////////////////////
contract ValidDataElementVuln {
    mapping(uint256 => uint256) public elements;
    event ElementStored(
        address indexed who,
        uint256 indexed id,
        uint256 value,
        ValidDataElementAttackType attack
    );

    function store(uint256 id, uint256 value) external {
        // ❌ no validation: attacker can store invalid or overflowing values
        elements[id] = value;
        emit ElementStored(msg.sender, id, value, ValidDataElementAttackType.MalformedInput);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates overflow and injection of missing fields
////////////////////////////////////////////////////////////////////////////////
contract Attack_ValidDataElement {
    ValidDataElementVuln public target;
    constructor(ValidDataElementVuln _t) { target = _t; }

    /// attempt to overflow by using max uint
    function overflowAttack(uint256 id) external {
        target.store(id, type(uint256).max);
    }

    /// simulate missing field by using zero for required non-zero
    function missingField(uint256 id) external {
        target.store(id, 0);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH INPUT VALIDATION
//    • Defense: InputValidation – require non-zero and below max limit
////////////////////////////////////////////////////////////////////////////////
contract ValidDataElementSafeInput {
    mapping(uint256 => uint256) public elements;
    uint256 public constant MAX_VALUE = 1_000_000;

    event ElementStored(
        address indexed who,
        uint256 indexed id,
        uint256 value,
        ValidDataElementDefenseType defense
    );

    function store(uint256 id, uint256 value) external {
        if (value == 0 || value > MAX_VALUE) revert VDE__InvalidInput();
        elements[id] = value;
        emit ElementStored(msg.sender, id, value, ValidDataElementDefenseType.InputValidation);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH SCHEMA VALIDATION
//    • Defense: SchemaValidation – only allow whitelisted IDs
////////////////////////////////////////////////////////////////////////////////
contract ValidDataElementSafeSchema {
    mapping(uint256 => uint256) public elements;
    mapping(uint256 => bool)  public allowedIds;
    address public owner;

    event ElementStored(
        address indexed who,
        uint256 indexed id,
        uint256 value,
        ValidDataElementDefenseType defense
    );

    error VDE__NotAllowed();

    constructor() {
        owner = msg.sender;
    }

    function setAllowed(uint256 id, bool ok) external {
        if (msg.sender != owner) revert VDE__NotAllowed();
        allowedIds[id] = ok;
    }

    function store(uint256 id, uint256 value) external {
        if (!allowedIds[id]) revert VDE__NotAllowed();
        elements[id] = value;
        emit ElementStored(msg.sender, id, value, ValidDataElementDefenseType.SchemaValidation);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH RANGE & TYPE ENFORCEMENT
//    • Defense: RangeValidation – enforce per-ID min/max  
//               TypeEnforcement – enforce value mod constraint
////////////////////////////////////////////////////////////////////////////////
contract ValidDataElementSafeAdvanced {
    struct Rules { uint256 min; uint256 max; uint256 mod; }
    mapping(uint256 => Rules) public rules;
    mapping(uint256 => uint256) public elements;
    address public owner;

    event ElementStored(
        address indexed who,
        uint256 indexed id,
        uint256 value,
        ValidDataElementDefenseType defense
    );

    error VDE__OutOfRange();
    error VDE__TypeMismatch();
    error VDE__NotAllowed();

    constructor() {
        owner = msg.sender;
    }

    function setRules(uint256 id, uint256 min, uint256 max, uint256 mod) external {
        if (msg.sender != owner) revert VDE__NotAllowed();
        rules[id] = Rules(min, max, mod);
    }

    function store(uint256 id, uint256 value) external {
        Rules memory r = rules[id];
        if (value < r.min || value > r.max) revert VDE__OutOfRange();
        if (r.mod != 0 && value % r.mod != 0) revert VDE__TypeMismatch();
        elements[id] = value;
        emit ElementStored(msg.sender, id, value, ValidDataElementDefenseType.RangeValidation);
    }
}
