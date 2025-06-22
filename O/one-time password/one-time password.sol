// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title OneTimePasswordSuite.sol
/// @notice On-chain analogues of “One-Time Password” (OTP) authentication patterns:
///   Types: HOTP, TOTP, SMS, ChallengeResponse  
///   AttackTypes: BruteForce, Replay, Phishing, MITM  
///   DefenseTypes: RateLimit, Expiry, OTPValidation, TwoFactor  

enum OneTimePasswordType         { HOTP, TOTP, SMS, ChallengeResponse }
enum OneTimePasswordAttackType   { BruteForce, Replay, Phishing, MITM }
enum OneTimePasswordDefenseType  { RateLimit, Expiry, OTPValidation, TwoFactor }

error OTP__TooManyRequests();
error OTP__Expired();
error OTP__InvalidOTP();
error OTP__No2FA();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE OTP SERVICE
//
//    • ❌ no rate-limit, no expiry → BruteForce, Replay
////////////////////////////////////////////////////////////////////////////////
contract OTPVuln {
    mapping(address => uint256) public currentOtp;
    event OTPGenerated(address indexed who, uint256 otp, OneTimePasswordType ptype);
    event OTPChecked(address indexed who, bool valid, OneTimePasswordAttackType attack);

    /// generate a new OTP (stubbed random)
    function generate(uint256 otp, OneTimePasswordType ptype) external {
        currentOtp[msg.sender] = otp;
        emit OTPGenerated(msg.sender, otp, ptype);
    }

    /// check OTP with no controls
    function check(uint256 otp) external {
        bool ok = (currentOtp[msg.sender] == otp);
        emit OTPChecked(msg.sender, ok, OneTimePasswordAttackType.BruteForce);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//
//    • brute-force attempts & replay last OTP
////////////////////////////////////////////////////////////////////////////////
contract Attack_OTP {
    OTPVuln public target;
    uint256 public lastOtp;

    constructor(OTPVuln _t) { target = _t; }

    function capture(uint256 otp) external {
        lastOtp = otp;
    }

    function bruteForce(uint256[] calldata guesses) external {
        for (uint i = 0; i < guesses.length; i++) {
            target.check(guesses[i]);
        }
    }

    function replay() external {
        target.check(lastOtp);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE OTP WITH RATE-LIMITING
//
//    • Defense: RateLimit – cap checks per block
////////////////////////////////////////////////////////////////////////////////
contract OTPSafeRateLimit {
    OTPVuln public legacy;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MAX_CALLS = 3;

    event OTPChecked(address indexed who, bool valid, OneTimePasswordDefenseType defense);

    constructor(OTPVuln _legacy) {
        legacy = _legacy;
    }

    error OTP__TooManyRequests();

    function check(uint256 otp) external {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert OTP__TooManyRequests();

        bool ok = (legacy.currentOtp(msg.sender) == otp);
        emit OTPChecked(msg.sender, ok, OneTimePasswordDefenseType.RateLimit);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE OTP WITH EXPIRY
//
//    • Defense: Expiry – OTP valid only for a limited time window
////////////////////////////////////////////////////////////////////////////////
contract OTPSafeExpiry {
    struct Entry { uint256 otp; uint256 expiry; }
    mapping(address => Entry) public store;
    uint256 public constant TTL = 5 minutes;

    event OTPGenerated(address indexed who, uint256 otp, OneTimePasswordDefenseType defense);
    event OTPChecked(address indexed who, bool valid, OneTimePasswordDefenseType defense);

    error OTP__Expired();

    function generate(uint256 otp) external {
        store[msg.sender] = Entry(otp, block.timestamp + TTL);
        emit OTPGenerated(msg.sender, otp, OneTimePasswordDefenseType.Expiry);
    }

    function check(uint256 otp) external {
        Entry memory e = store[msg.sender];
        if (block.timestamp > e.expiry) revert OTP__Expired();
        bool ok = (e.otp == otp);
        emit OTPChecked(msg.sender, ok, OneTimePasswordDefenseType.Expiry);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED OTP WITH TWO-FACTOR & VALIDATION
//
//    • Defense: OTPValidation – require matching code  
//               TwoFactor – require prior MFA step
////////////////////////////////////////////////////////////////////////////////
contract OTPSafeAdvanced {
    mapping(address => uint256) public currentOtp;
    mapping(address => bool)    public mfaPassed;

    event OTPGenerated(address indexed who, uint256 otp, OneTimePasswordDefenseType defense);
    event MFAApproved(address indexed who, OneTimePasswordDefenseType defense);
    event OTPChecked(address indexed who, bool valid, OneTimePasswordDefenseType defense);

    error OTP__No2FA();
    error OTP__InvalidOTP();

    /// stub MFA step
    function verifyMFA(bytes32 token) external {
        // stub check: token == keccak256(user||blockhash)
        bytes32 expected = keccak256(abi.encodePacked(msg.sender, blockhash(block.number - 1)));
        require(token == expected, "invalid MFA token");
        mfaPassed[msg.sender] = true;
        emit MFAApproved(msg.sender, OneTimePasswordDefenseType.TwoFactor);
    }

    function generate(uint256 otp) external {
        require(mfaPassed[msg.sender], "MFA required");
        currentOtp[msg.sender] = otp;
        mfaPassed[msg.sender] = false;
        emit OTPGenerated(msg.sender, otp, OneTimePasswordDefenseType.OTPValidation);
    }

    function check(uint256 otp) external {
        bool ok = (currentOtp[msg.sender] == otp);
        if (!ok) revert OTP__InvalidOTP();
        emit OTPChecked(msg.sender, true, OneTimePasswordDefenseType.OTPValidation);
    }
}
