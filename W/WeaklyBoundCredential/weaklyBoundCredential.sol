// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title WeaklyBoundCredentialSuite.sol
/// @notice On‐chain analogues of “Weakly Bound Credential” patterns:
///   Types: PasswordOnly, SessionCookie, OAuthToken, JWT  
///   AttackTypes: Phishing, CredentialReplay, SessionHijack, TokenForgery  
///   DefenseTypes: MFA, DeviceBinding, TokenBinding, RateLimit

enum WeaklyBoundCredentialType       { PasswordOnly, SessionCookie, OAuthToken, JWT }
enum WeaklyBoundCredentialAttackType { Phishing, CredentialReplay, SessionHijack, TokenForgery }
enum WeaklyBoundCredentialDefenseType{ MFA, DeviceBinding, TokenBinding, RateLimit }

error WBC__NotAuthorized();
error WBC__NoMFA();
error WBC__InvalidDevice();
error WBC__TooManyRequests();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE AUTHENTICATOR
//
//    • ❌ no binding: any valid credential may be replayed → CredentialReplay
////////////////////////////////////////////////////////////////////////////////
contract WeaklyBoundCredentialVuln {
    mapping(address => bytes32) public cred; // stored credential
    event Authenticated(
        address indexed who,
        WeaklyBoundCredentialType ctype,
        bool                      success,
        WeaklyBoundCredentialAttackType attack
    );

    function register(bytes32 credential, WeaklyBoundCredentialType ctype) external {
        cred[msg.sender] = credential;
    }

    function authenticate(bytes32 credential, WeaklyBoundCredentialType ctype) external {
        bool ok = (cred[msg.sender] == credential);
        emit Authenticated(msg.sender, ctype, ok, WeaklyBoundCredentialAttackType.CredentialReplay);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//
//    • simulates phishing & session hijacking
////////////////////////////////////////////////////////////////////////////////
contract Attack_WeaklyBoundCredential {
    WeaklyBoundCredentialVuln public target;
    bytes32 public stolen;
    address public victim;

    constructor(WeaklyBoundCredentialVuln _t) { target = _t; }

    function phish(address _victim, bytes32 credential) external {
        victim = _victim;
        stolen = credential;
    }

    function replay(WeaklyBoundCredentialType ctype) external {
        // impersonate victim
        target.authenticate(stolen, ctype);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH MFA
//
//    • ✅ Defense: MFA – require one‐time code before authenticate
////////////////////////////////////////////////////////////////////////////////
contract WBCSafeMFA {
    mapping(address => bytes32) public cred;
    mapping(address => bytes32) public otp;
    mapping(address => bool)    public mfaOk;

    event OTPIssued(address indexed who, bytes32 token, WeaklyBoundCredentialDefenseType defense);
    event Authenticated(
        address indexed who,
        WeaklyBoundCredentialType ctype,
        WeaklyBoundCredentialDefenseType defense
    );

    error WBC__NoMFA();

    function register(bytes32 credential, WeaklyBoundCredentialType) external {
        cred[msg.sender] = credential;
    }

    function issueOTP(address user, bytes32 token) external {
        otp[user] = token;
        emit OTPIssued(user, token, WeaklyBoundCredentialDefenseType.MFA);
    }

    function verifyOTP(bytes32 token) external {
        require(otp[msg.sender] == token, "bad OTP");
        mfaOk[msg.sender] = true;
        delete otp[msg.sender];
    }

    function authenticate(bytes32 credential, WeaklyBoundCredentialType ctype) external {
        if (!mfaOk[msg.sender]) revert WBC__NoMFA();
        mfaOk[msg.sender] = false;
        require(cred[msg.sender] == credential, "credential mismatch");
        emit Authenticated(msg.sender, ctype, WeaklyBoundCredentialDefenseType.MFA);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH DEVICE BINDING
//
//    • ✅ Defense: DeviceBinding – tie sessions to a device ID
////////////////////////////////////////////////////////////////////////////////
contract WBCSafeDeviceBinding {
    mapping(address => bytes32) public cred;
    mapping(address => bytes32) public deviceOf;
    event Authenticated(
        address indexed who,
        WeaklyBoundCredentialType ctype,
        WeaklyBoundCredentialDefenseType defense
    );

    error WBC__InvalidDevice();

    function register(bytes32 credential, bytes32 deviceId, WeaklyBoundCredentialType) external {
        cred[msg.sender] = credential;
        deviceOf[msg.sender] = deviceId;
    }

    function authenticate(bytes32 credential, WeaklyBoundCredentialType ctype, bytes32 deviceId) external {
        if (deviceOf[msg.sender] != deviceId) revert WBC__InvalidDevice();
        require(cred[msg.sender] == credential, "credential mismatch");
        emit Authenticated(msg.sender, ctype, WeaklyBoundCredentialDefenseType.DeviceBinding);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH TOKEN BINDING & RATE LIMIT
//
//    • ✅ Defense: TokenBinding – bind a fresh token per session  
//               RateLimit – cap auth attempts per block
////////////////////////////////////////////////////////////////////////////////
contract WBCSafeAdvanced {
    mapping(address => bytes32) public cred;
    mapping(address => bytes32) public sessionToken;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MAX_CALLS = 3;

    event Authenticated(
        address indexed who,
        WeaklyBoundCredentialType ctype,
        WeaklyBoundCredentialDefenseType defense
    );

    error WBC__TooManyRequests();

    function register(bytes32 credential, WeaklyBoundCredentialType) external {
        cred[msg.sender] = credential;
    }

    function newSessionToken(address user, bytes32 token) external {
        sessionToken[user] = token;
    }

    function authenticate(
        bytes32 credential,
        WeaklyBoundCredentialType ctype,
        bytes32 token
    ) external {
        // rate‐limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert WBC__TooManyRequests();

        require(cred[msg.sender] == credential, "credential mismatch");
        require(sessionToken[msg.sender] == token, "invalid session token");
        emit Authenticated(msg.sender, ctype, WeaklyBoundCredentialDefenseType.TokenBinding);
    }
}
