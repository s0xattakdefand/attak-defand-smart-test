// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title ValidLengthSuite.sol
/// @notice On-chain analogues of “Valid Length” input validation patterns:
///   Types: Exact, Min, Max, Range  
///   AttackTypes: TooShort, TooLong, BufferOverflow  
///   DefenseTypes: LengthCheck, BoundedArray, RegexValidation, RateLimit  

enum ValidLengthType         { Exact, Min, Max, Range }
enum ValidLengthAttackType   { TooShort, TooLong, BufferOverflow }
enum ValidLengthDefenseType  { LengthCheck, BoundedArray, RegexValidation, RateLimit }

error VL__TooShort();
error VL__TooLong();
error VL__Overflow();
error VL__TooManyRequests();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE STORAGE (no length checks)
//    • Attack: TooShort or TooLong
////////////////////////////////////////////////////////////////////////////////
contract ValidLengthVuln {
    mapping(uint256 => string) public data;
    event LengthStored(
        address indexed who,
        uint256 indexed id,
        uint256             length,
        ValidLengthAttackType attack
    );

    function store(uint256 id, string calldata s) external {
        data[id] = s;
        emit LengthStored(msg.sender, id, bytes(s).length, 
            bytes(s).length == 0 ? ValidLengthAttackType.TooShort : 
            PackedLength(bytes(s).length), 
            ValidLengthAttackType.BufferOverflow);
    }

    // helper to choose attack type for too long (>256) stub
    function PackedLength(uint256 l) private pure returns (ValidLengthAttackType) {
        if (l > 256) return ValidLengthAttackType.TooLong;
        return ValidLengthAttackType.BufferOverflow;
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • Attack: store empty or oversized string to cause errors
////////////////////////////////////////////////////////////////////////////////
contract Attack_ValidLength {
    ValidLengthVuln public target;
    string public large;

    constructor(ValidLengthVuln _t) {
        target = _t;
        // simulate large string (overflow)
        large = string(new bytes(300));
    }

    function tooShort(uint256 id) external {
        target.store(id, "");
    }

    function tooLong(uint256 id) external {
        target.store(id, large);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE EXACT-LENGTH CHECK
//    • Defense: LengthCheck – require exact preset length
////////////////////////////////////////////////////////////////////////////////
contract ValidLengthSafeExact {
    mapping(uint256 => string) public data;
    mapping(uint256 => uint256) public exactLen;
    event LengthStored(
        address indexed who,
        uint256 indexed id,
        uint256             length,
        ValidLengthDefenseType defense
    );

    error VL__InvalidLength();

    /// owner sets required exact length per id
    function setExactLen(uint256 id, uint256 len) external {
        exactLen[id] = len;
    }

    function store(uint256 id, string calldata s) external {
        uint256 l = bytes(s).length;
        if (l != exactLen[id]) revert VL__InvalidLength();
        data[id] = s;
        emit LengthStored(msg.sender, id, l, ValidLengthDefenseType.LengthCheck);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE RANGE-LENGTH CHECK
//    • Defense: BoundedArray – enforce min ≤ len ≤ max
////////////////////////////////////////////////////////////////////////////////
contract ValidLengthSafeRange {
    mapping(uint256 => string) public data;
    mapping(uint256 => uint256) public minLen;
    mapping(uint256 => uint256) public maxLen;
    event LengthStored(
        address indexed who,
        uint256 indexed id,
        uint256             length,
        ValidLengthDefenseType defense
    );

    error VL__TooShort();
    error VL__TooLong();

    /// owner sets [min,max] per id
    function setBounds(uint256 id, uint256 minL, uint256 maxL) external {
        require(minL <= maxL, "bad bounds");
        minLen[id] = minL;
        maxLen[id] = maxL;
    }

    function store(uint256 id, string calldata s) external {
        uint256 l = bytes(s).length;
        if (l < minLen[id]) revert VL__TooShort();
        if (l > maxLen[id]) revert VL__TooLong();
        data[id] = s;
        emit LengthStored(msg.sender, id, l, ValidLengthDefenseType.BoundedArray);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH REGEX CHECK & RATE-LIMIT
//    • Defense: RegexValidation – require simple prefix check  
//               RateLimit – cap calls per block
////////////////////////////////////////////////////////////////////////////////
contract ValidLengthSafeAdvanced {
    mapping(uint256 => string) public data;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MAX_CALLS = 5;
    event LengthStored(
        address indexed who,
        uint256 indexed id,
        uint256             length,
        ValidLengthDefenseType defense
    );

    error VL__TooManyRequests();
    error VL__InvalidFormat();

    /// store only if string begins with "v:" (simple regex stub)
    function store(uint256 id, string calldata s) external {
        // rate-limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert VL__TooManyRequests();

        bytes memory b = bytes(s);
        require(b.length >= 2, "too short for format");
        // regex stub: must start with "v:"
        if (b[0] != "v" || b[1] != ":") revert VL__InvalidFormat();

        data[id] = s;
        emit LengthStored(msg.sender, id, b.length, ValidLengthDefenseType.RegexValidation);
    }
}
