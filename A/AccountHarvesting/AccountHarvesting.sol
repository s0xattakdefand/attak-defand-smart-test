// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AccountHarvestingSuite.sol
/// @notice On-chain analogues of “Account Harvesting” patterns:
///   Types: Targeted, Bulk  
///   AttackTypes: Enumeration, CredentialStuffing  
///   DefenseTypes: RateLimit, CAPTCHAVerification, UniformResponse, AccountLockout  

enum AccountHarvestingType        { Targeted, Bulk }
enum AccountHarvestingAttackType  { Enumeration, CredentialStuffing }
enum AccountHarvestingDefenseType { RateLimit, CAPTCHAVerification, UniformResponse, AccountLockout }

error AH__TooManyRequests();
error AH__BadCaptcha();
error AH__Locked();
error AH__InvalidResponse();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE CHECKER (no limits, reveals existence)
//    • Attack: Enumeration
////////////////////////////////////////////////////////////////////////////////
contract AccountHarvestVuln {
    mapping(string => bool) public userExists;
    event HarvestChecked(
        address indexed by,
        string            username,
        bool              exists,
        AccountHarvestingAttackType attack
    );

    constructor(string[] memory initialUsers) {
        for (uint i = 0; i < initialUsers.length; i++) {
            userExists[initialUsers[i]] = true;
        }
    }

    /// ❌ no rate-limit or uniformity: returns true/false directly
    function checkUser(string calldata username) external {
        bool exists = userExists[username];
        emit HarvestChecked(msg.sender, username, exists, AccountHarvestingAttackType.Enumeration);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB (mass enumeration & credential stuffing)
//    • Attack: Bulk enumeration, CredentialStuffing
////////////////////////////////////////////////////////////////////////////////
contract Attack_AccountHarvest {
    AccountHarvestVuln public target;
    constructor(AccountHarvestVuln _t) { target = _t; }

    /// bulk‐check many usernames
    function bulkCheck(string[] calldata names) external {
        for (uint i = 0; i < names.length; i++) {
            target.checkUser(names[i]);
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE RATE-LIMITED CHECKER
//    • Defense: RateLimit – cap checks per block
////////////////////////////////////////////////////////////////////////////////
contract AccountHarvestSafeRateLimit {
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public countInBlock;
    uint256 public constant MAX_PER_BLOCK = 5;

    mapping(string => bool) public userExists;
    event HarvestChecked(
        address indexed by,
        string            username,
        AccountHarvestingDefenseType defense
    );

    error AH__TooManyRequests();

    constructor(string[] memory initialUsers) {
        for (uint i = 0; i < initialUsers.length; i++) {
            userExists[initialUsers[i]] = true;
        }
    }

    function checkUser(string calldata username) external {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender]++;
        if (countInBlock[msg.sender] > MAX_PER_BLOCK) revert AH__TooManyRequests();

        emit HarvestChecked(msg.sender, username, AccountHarvestingDefenseType.RateLimit);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE CAPTCHA-PROTECTED CHECKER
//    • Defense: CAPTCHAVerification – require valid token
////////////////////////////////////////////////////////////////////////////////
contract AccountHarvestSafeCaptcha {
    mapping(string => bool) public userExists;
    mapping(address => bytes32) public captchaToken;
    event HarvestChecked(
        address indexed by,
        string            username,
        AccountHarvestingDefenseType defense
    );

    error AH__BadCaptcha();

    constructor(string[] memory initialUsers) {
        for (uint i = 0; i < initialUsers.length; i++) {
            userExists[initialUsers[i]] = true;
        }
    }

    /// owner assigns CAPTCHA tokens off-chain
    function setCaptchaToken(address user, bytes32 token) external {
        // in practice restricted to admin
        captchaToken[user] = token;
    }

    function checkUser(string calldata username, bytes32 token) external {
        if (captchaToken[msg.sender] != token) revert AH__BadCaptcha();
        emit HarvestChecked(msg.sender, username, AccountHarvestingDefenseType.CAPTCHAVerification);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH UNIFORM RESPONSE & LOCKOUT
//    • Defense: UniformResponse & AccountLockout
////////////////////////////////////////////////////////////////////////////////
contract AccountHarvestSafeAdvanced {
    mapping(string => bool) public userExists;
    mapping(address => uint256) public failCount;
    mapping(address => bool)    public locked;
    uint256 public constant MAX_FAIL = 3;

    event HarvestChecked(
        address indexed by,
        string            username,
        AccountHarvestingDefenseType defense
    );

    error AH__Locked();

    constructor(string[] memory initialUsers) {
        for (uint i = 0; i < initialUsers.length; i++) {
            userExists[initialUsers[i]] = true;
        }
    }

    /// uniform response: always emits same event regardless of existence
    function checkUser(string calldata username) external {
        if (locked[msg.sender]) revert AH__Locked();

        // simulate reveal but do not indicate existence
        bool exists = userExists[username];
        // track failures to lock out credential stuffing attempts
        if (!exists) {
            failCount[msg.sender]++;
            if (failCount[msg.sender] >= MAX_FAIL) {
                locked[msg.sender] = true;
            }
        } else {
            // reset on hit
            failCount[msg.sender] = 0;
        }

        emit HarvestChecked(msg.sender, username, AccountHarvestingDefenseType.UniformResponse);
    }
}
