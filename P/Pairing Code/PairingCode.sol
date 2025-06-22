// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title PairingCodeSuite.sol
/// @notice On-chain analogues of “Pairing Code” device‐pairing patterns:
///   Types: Numeric, QR, SoftToken, Biometric  
///   AttackTypes: BruteForce, Replay, MITM, SocialEngineering  
///   DefenseTypes: RateLimit, Expiry, OTPValidation, MutualAuth

enum PairingCodeType          { Numeric, QR, SoftToken, Biometric }
enum PairingCodeAttackType    { BruteForce, Replay, MITM, SocialEngineering }
enum PairingCodeDefenseType   { RateLimit, Expiry, OTPValidation, MutualAuth }

error PC__TooManyAttempts();
error PC__Expired();
error PC__BadCode();
error PC__NotAuthorized();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE PAIRING CENTER
//
//    • no limits, no freshness → BruteForce, Replay
////////////////////////////////////////////////////////////////////////////////
contract PairingCodeVuln {
    mapping(address => bytes32) public codes;
    event CodeGenerated(address indexed who, bytes32 code, PairingCodeType ptype);
    event Paired(address indexed who, address indexed device, bool success, PairingCodeAttackType attack);

    /// generate code once
    function generateCode(bytes32 code, PairingCodeType ptype) external {
        codes[msg.sender] = code;
        emit CodeGenerated(msg.sender, code, ptype);
    }

    /// naive pair: any matching code works, no expiry
    function pair(address device, bytes32 code) external {
        bool ok = (codes[msg.sender] == code);
        emit Paired(msg.sender, device, ok, PairingCodeAttackType.BruteForce);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//
//    • brute‐force guesses & replay stolen codes
////////////////////////////////////////////////////////////////////////////////
contract Attack_PairingCode {
    PairingCodeVuln public target;
    bytes32 public captured;

    constructor(PairingCodeVuln _t) { target = _t; }

    function steal(bytes32 code) external {
        captured = code;
    }

    function bruteForce(bytes32[] calldata guesses) external {
        for (uint i; i < guesses.length; i++) {
            target.pair(address(0xdead), guesses[i]);
        }
    }

    function replay(address device) external {
        target.pair(device, captured);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH RATE LIMITING
//
//    • Defense: RateLimit – cap pairing attempts per block
////////////////////////////////////////////////////////////////////////////////
contract PairingCodeSafeRateLimit {
    mapping(address => bytes32) public codes;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public triesInBlock;
    uint256 public constant MAX_TRIES = 3;

    event CodeGenerated(address indexed who, bytes32 code, PairingCodeType ptype, PairingCodeDefenseType defense);
    event Paired(address indexed who, address indexed device, bool success, PairingCodeDefenseType defense);

    error PC__TooManyAttempts();

    function generateCode(bytes32 code, PairingCodeType ptype) external {
        codes[msg.sender] = code;
        emit CodeGenerated(msg.sender, code, ptype, PairingCodeDefenseType.RateLimit);
    }

    function pair(address device, bytes32 code) external {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender] = block.number;
            triesInBlock[msg.sender] = 0;
        }
        triesInBlock[msg.sender]++;
        if (triesInBlock[msg.sender] > MAX_TRIES) revert PC__TooManyAttempts();

        bool ok = (codes[msg.sender] == code);
        emit Paired(msg.sender, device, ok, PairingCodeDefenseType.RateLimit);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH EXPIRY
//
//    • Defense: Expiry – code valid only for a time window
////////////////////////////////////////////////////////////////////////////////
contract PairingCodeSafeExpiry {
    struct Entry { bytes32 code; uint256 expiry; }
    mapping(address => Entry) public store;
    uint256 public constant TTL = 5 minutes;

    event CodeGenerated(address indexed who, bytes32 code, PairingCodeType ptype, PairingCodeDefenseType defense);
    event Paired(address indexed who, address indexed device, bool success, PairingCodeDefenseType defense);

    error PC__Expired();

    function generateCode(bytes32 code, PairingCodeType ptype) external {
        store[msg.sender] = Entry(code, block.timestamp + TTL);
        emit CodeGenerated(msg.sender, code, ptype, PairingCodeDefenseType.Expiry);
    }

    function pair(address device, bytes32 code) external {
        Entry memory e = store[msg.sender];
        if (block.timestamp > e.expiry) revert PC__Expired();
        bool ok = (e.code == code);
        emit Paired(msg.sender, device, ok, PairingCodeDefenseType.Expiry);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH OTP VALIDATION & MUTUAL AUTH
//
//    • Defense: OTPValidation – require one‐time password step  
//               MutualAuth – both sides verify each other
////////////////////////////////////////////////////////////////////////////////
contract PairingCodeSafeAdvanced {
    mapping(address => bytes32) public codes;
    mapping(address => bool)    public otpOk;
    mapping(address => bytes32) public otpToken;

    event CodeGenerated(address indexed who, bytes32 code, PairingCodeType ptype, PairingCodeDefenseType defense);
    event OTPVerified(address indexed who, bytes32 token, PairingCodeDefenseType defense);
    event Paired(address indexed who, address indexed device, bool success, PairingCodeDefenseType defense);

    error PC__BadOTP();
    error PC__NotAuthorized();

    /// owner issues OTP token off‐chain
    function setOtpToken(address user, bytes32 token) external {
        otpToken[user] = token;
    }

    function verifyOtp(bytes32 token) external {
        if (otpToken[msg.sender] != token) revert PC__BadOTP();
        otpOk[msg.sender] = true;
        delete otpToken[msg.sender];
        emit OTPVerified(msg.sender, token, PairingCodeDefenseType.OTPValidation);
    }

    function generateCode(bytes32 code, PairingCodeType ptype) external {
        require(otpOk[msg.sender], "OTP required");
        codes[msg.sender] = code;
        otpOk[msg.sender] = false;
        emit CodeGenerated(msg.sender, code, ptype, PairingCodeDefenseType.OTPValidation);
    }

    function pair(address device, bytes32 code) external {
        // mutual auth: device must also have code registered
        if (codes[msg.sender] != code || codes[device] != code) revert PC__NotAuthorized();
        // both sides verify OTP earlier
        if (!otpOk[msg.sender] || !otpOk[device]) revert PC__NotAuthorized();
        emit Paired(msg.sender, device, true, PairingCodeDefenseType.MutualAuth);
    }
}
