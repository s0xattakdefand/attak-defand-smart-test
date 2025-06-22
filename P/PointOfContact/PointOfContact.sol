// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title PointOfContactSuite.sol
/// @notice On-chain analogues of “Point of Contact” interaction patterns:
///   Types: Support, Sales, Legal, Technical  
///   AttackTypes: Phishing, Impersonation, Spam, Flooding  
///   DefenseTypes: IdentityVerification, MFAVerification, RateLimit, AuditLogging  

enum PointOfContactType        { Support, Sales, Legal, Technical }
enum PointOfContactAttackType  { Phishing, Impersonation, Spam, Flooding }
enum PointOfContactDefenseType { IdentityVerification, MFAVerification, RateLimit, AuditLogging }

error POC__NotVerified();
error POC__NoOTP();
error POC__TooManyRequests();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE CONTACT POINT
//    • ❌ no checks: anyone may send any message → Phishing, Spam
////////////////////////////////////////////////////////////////////////////////
contract PointOfContactVuln {
    event ContactSent(
        address indexed who,
        uint256           contactId,
        PointOfContactType ctype,
        string            message,
        PointOfContactAttackType attack
    );

    function contact(uint256 contactId, PointOfContactType ctype, string calldata message) external {
        emit ContactSent(msg.sender, contactId, ctype, message, PointOfContactAttackType.Phishing);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates flooding and impersonation
////////////////////////////////////////////////////////////////////////////////
contract Attack_PointOfContact {
    PointOfContactVuln public target;

    constructor(PointOfContactVuln _t) {
        target = _t;
    }

    function spam(uint256 contactId, PointOfContactType ctype, string calldata msg_, uint256 times) external {
        for (uint i = 0; i < times; i++) {
            target.contact(contactId, ctype, msg_);
        }
    }

    function impersonate(uint256 contactId, PointOfContactType ctype, string calldata fakeMsg) external {
        target.contact(contactId, ctype, fakeMsg);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE CONTACT WITH IDENTITY VERIFICATION
//    • ✅ Defense: IdentityVerification – only verified users may send
////////////////////////////////////////////////////////////////////////////////
contract PointOfContactSafeID {
    mapping(address => bool) public verified;
    address public admin;

    event ContactSent(
        address indexed who,
        uint256           contactId,
        PointOfContactType ctype,
        string            message,
        PointOfContactDefenseType defense
    );

    error POC__NotVerified();

    constructor() {
        admin = msg.sender;
    }

    function setVerified(address user, bool ok) external {
        require(msg.sender == admin, "only admin");
        verified[user] = ok;
    }

    function contact(uint256 contactId, PointOfContactType ctype, string calldata message) external {
        if (!verified[msg.sender]) revert POC__NotVerified();
        emit ContactSent(msg.sender, contactId, ctype, message, PointOfContactDefenseType.IdentityVerification);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE CONTACT WITH MFA VERIFICATION
//    • ✅ Defense: MFAVerification – require OTP before send
////////////////////////////////////////////////////////////////////////////////
contract PointOfContactSafeMFA {
    mapping(address => bool)    public otpPassed;
    mapping(address => bytes32) public otpToken;

    event ContactSent(
        address indexed who,
        uint256           contactId,
        PointOfContactType ctype,
        string            message,
        PointOfContactDefenseType defense
    );

    error POC__NoOTP();

    /// admin assigns one-time tokens off-chain
    function setOTPToken(address user, bytes32 token) external {
        otpToken[user] = token;
    }

    function verifyOTP(bytes32 token) external {
        if (otpToken[msg.sender] != token) revert POC__NoOTP();
        otpPassed[msg.sender] = true;
        delete otpToken[msg.sender];
    }

    function contact(uint256 contactId, PointOfContactType ctype, string calldata message) external {
        if (!otpPassed[msg.sender]) revert POC__NoOTP();
        otpPassed[msg.sender] = false;
        emit ContactSent(msg.sender, contactId, ctype, message, PointOfContactDefenseType.MFAVerification);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH RATE LIMITING & AUDIT LOGGING
//    • ✅ Defense: RateLimit – cap contacts per block  
//               AuditLogging – record all interactions
////////////////////////////////////////////////////////////////////////////////
contract PointOfContactSafeAdvanced {
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MAX_CALLS = 3;

    event ContactSent(
        address indexed who,
        uint256           contactId,
        PointOfContactType ctype,
        string            message,
        PointOfContactDefenseType defense
    );
    event AuditLog(
        address indexed who,
        uint256           contactId,
        PointOfContactType ctype,
        string            message,
        PointOfContactDefenseType defense
    );

    error POC__TooManyRequests();

    function contact(uint256 contactId, PointOfContactType ctype, string calldata message) external {
        // rate-limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert POC__TooManyRequests();

        // audit log
        emit AuditLog(msg.sender, contactId, ctype, message, PointOfContactDefenseType.AuditLogging);
        // main event
        emit ContactSent(msg.sender, contactId, ctype, message, PointOfContactDefenseType.RateLimit);
    }
}
