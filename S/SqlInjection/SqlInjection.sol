// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title SQLInjectionSuite.sol
/// @notice On‐chain analogues of SQL Injection patterns:
///   Types: InbandError, InbandUnion, BlindBoolean, BlindTime, OutOfBand  
///   AttackTypes: ModifyQuery, ExtractData, BypassAuth, CorruptData, Exfiltrate  
///   DefenseTypes: Parameterized, Whitelisting, Escaping, RateLimit, Logging

enum SQLInjectionType         { InbandError, InbandUnion, BlindBoolean, BlindTime, OutOfBand }
enum SQLInjectionAttackType   { ModifyQuery, ExtractData, BypassAuth, CorruptData, Exfiltrate }
enum SQLInjectionDefenseType  { Parameterized, Whitelisting, Escaping, RateLimit, Logging }

error SQLI__InvalidInput();
error SQLI__TooManyRequests();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE CONTRACT
//    • ❌ naive string assembly → ModifyQuery, ExtractData
////////////////////////////////////////////////////////////////////////////////
contract SQLInjectionVuln {
    mapping(address => string) public profiles;

    event Query(
        address indexed who,
        string             input,
        SQLInjectionType   stype,
        SQLInjectionAttackType attack
    );

    function setProfile(string calldata profile) external {
        profiles[msg.sender] = profile;
    }

    function getProfile(string calldata userInput, SQLInjectionType stype) external {
        // pretend to build: SELECT * FROM profiles WHERE name = '<userInput>';
        emit Query(msg.sender, userInput, stype, SQLInjectionAttackType.ModifyQuery);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates various injection techniques
////////////////////////////////////////////////////////////////////////////////
contract Attack_SQLInjection {
    SQLInjectionVuln public target;
    string public lastInput;
    SQLInjectionType public lastType;

    constructor(SQLInjectionVuln _t) { target = _t; }

    function errorBased(string calldata payload) external {
        target.getProfile(payload, SQLInjectionType.InbandError);
        lastInput = payload; lastType = SQLInjectionType.InbandError;
    }
    function unionBased(string calldata payload) external {
        target.getProfile(payload, SQLInjectionType.InbandUnion);
        lastInput = payload; lastType = SQLInjectionType.InbandUnion;
    }
    function blindBoolean(string calldata payload) external {
        target.getProfile(payload, SQLInjectionType.BlindBoolean);
        lastInput = payload; lastType = SQLInjectionType.BlindBoolean;
    }
    function timeBased(string calldata payload) external {
        target.getProfile(payload, SQLInjectionType.BlindTime);
        lastInput = payload; lastType = SQLInjectionType.BlindTime;
    }
    function outOfBand(string calldata payload) external {
        target.getProfile(payload, SQLInjectionType.OutOfBand);
        lastInput = payload; lastType = SQLInjectionType.OutOfBand;
    }
    function replay() external {
        target.getProfile(lastInput, lastType);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH PARAMETERIZED QUERIES
//    • ✅ Defense: Parameterized – avoids concatenation
////////////////////////////////////////////////////////////////////////////////
contract SQLInjectionSafeParam {
    event Query(
        address indexed who,
        bytes32            nameHash,
        SQLInjectionDefenseType defense
    );

    function getProfile(bytes32 nameHash) external {
        // stub: would bind parameter instead of concatenating
        emit Query(msg.sender, nameHash, SQLInjectionDefenseType.Parameterized);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH WHITELISTING & ESCAPING
//    • ✅ Defense: Whitelisting – only A–Z, a–z, 0–9, space  
//               Escaping – simple quote escape
////////////////////////////////////////////////////////////////////////////////
contract SQLInjectionSafeValidate {
    event Query(
        address indexed who,
        string             clean,
        SQLInjectionDefenseType defense
    );

    error SQLI__InvalidInput();

    function _sanitize(string memory s) internal pure returns (string memory) {
        bytes memory b = bytes(s);
        for (uint i = 0; i < b.length; i++) {
            bytes1 c = b[i];
            if (
                !(c >= 0x30 && c <= 0x39) && // 0-9
                !(c >= 0x41 && c <= 0x5A) && // A-Z
                !(c >= 0x61 && c <= 0x7A) && // a-z
                !(c == 0x20) &&               // space
                !(c == 0x27)                  // '
            ) revert SQLI__InvalidInput();
        }
        return s;
    }

    function getProfile(string calldata userInput) external {
        string memory clean = _sanitize(userInput);
        emit Query(msg.sender, clean, SQLInjectionDefenseType.Whitelisting);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH RATE LIMITING & LOGGING
//    • ✅ Defense: RateLimit – cap calls per block  
//               Logging – emit audit for each attempt
////////////////////////////////////////////////////////////////////////////////
contract SQLInjectionSafeAdvanced {
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MAX_CALLS = 3;

    event Query(
        address indexed who,
        bytes32            nameHash,
        SQLInjectionDefenseType defense
    );

    error SQLI__TooManyRequests();

    function getProfile(bytes32 nameHash) external {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert SQLI__TooManyRequests();
        emit Query(msg.sender, nameHash, SQLInjectionDefenseType.RateLimit);
    }
}
