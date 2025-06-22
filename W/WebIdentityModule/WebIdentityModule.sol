// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title WebIdentityModuleSuite.sol
/// @notice On‐chain analogues of “Web Identity Module” patterns:
///   Types: PasswordAuth, OAuth, WebAuthn, SAML  
///   AttackTypes: Phishing, TokenReplay, CredentialStuffing, TokenStealing  
///   DefenseTypes: InputValidation, RateLimiting, SignatureValidation, ContinuousMonitoring

enum WebIdentityModuleType        { PasswordAuth, OAuth, WebAuthn, SAML }
enum WebIdentityModuleAttackType  { Phishing, TokenReplay, CredentialStuffing, TokenStealing }
enum WebIdentityModuleDefenseType { InputValidation, RateLimiting, SignatureValidation, ContinuousMonitoring }

error WIM__InvalidInput();
error WIM__TooManyRequests();
error WIM__Unauthorized();
error WIM__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE IDENTITY MODULE
//    • ❌ no validation or limits: anyone may register/login → TokenReplay
////////////////////////////////////////////////////////////////////////////////
contract WIMVuln {
    mapping(address => bytes32) public tokens;
    event Registered(address indexed who, WebIdentityModuleType itype);
    event LoggedIn(address indexed who, bytes32 token, WebIdentityModuleType itype, WebIdentityModuleAttackType attack);

    function register(WebIdentityModuleType itype, bytes32 token) external {
        tokens[msg.sender] = token;
        emit Registered(msg.sender, itype);
    }

    function login(bytes32 token, WebIdentityModuleType itype) external {
        // no validation: accepts any token
        tokens[msg.sender] = token;
        emit LoggedIn(msg.sender, token, itype, WebIdentityModuleAttackType.TokenReplay);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates phishing and credential stuffing
////////////////////////////////////////////////////////////////////////////////
contract Attack_WIM {
    WIMVuln public target;
    bytes32 public stolen;

    constructor(WIMVuln _t) { target = _t; }

    function phish(address victim) external {
        stolen = target.tokens(victim);
    }

    function replayLogin(WebIdentityModuleType itype) external {
        target.login(stolen, itype);
    }

    function credentialStuff(address user, bytes32 guessToken, WebIdentityModuleType itype) external {
        target.login(guessToken, itype);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH INPUT VALIDATION
//    • ✅ Defense: InputValidation – reject empty or malformed tokens
////////////////////////////////////////////////////////////////////////////////
contract WIMSafeValidate {
    mapping(address => bytes32) public tokens;
    event Registered(address indexed who, WebIdentityModuleType itype, WebIdentityModuleDefenseType defense);
    event LoggedIn(address indexed who, WebIdentityModuleType itype, WebIdentityModuleDefenseType defense);

    error WIM__InvalidInput();

    function register(WebIdentityModuleType itype, bytes32 token) external {
        if (token == bytes32(0)) revert WIM__InvalidInput();
        tokens[msg.sender] = token;
        emit Registered(msg.sender, itype, WebIdentityModuleDefenseType.InputValidation);
    }

    function login(bytes32 token, WebIdentityModuleType itype) external {
        if (token == bytes32(0)) revert WIM__InvalidInput();
        require(tokens[msg.sender] == token, "token mismatch");
        emit LoggedIn(msg.sender, itype, WebIdentityModuleDefenseType.InputValidation);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH RATE‐LIMITING
//    • ✅ Defense: RateLimiting – cap login attempts per block
////////////////////////////////////////////////////////////////////////////////
contract WIMSafeRateLimit {
    mapping(address => bytes32) public tokens;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public loginsInBlock;
    uint256 public constant MAX_LOGINS = 3;

    event Registered(address indexed who, WebIdentityModuleType itype, WebIdentityModuleDefenseType defense);
    event LoggedIn(address indexed who, WebIdentityModuleType itype, WebIdentityModuleDefenseType defense);

    error WIM__TooManyRequests();

    function register(WebIdentityModuleType itype, bytes32 token) external {
        tokens[msg.sender] = token;
        emit Registered(msg.sender, itype, WebIdentityModuleDefenseType.RateLimiting);
    }

    function login(bytes32 token, WebIdentityModuleType itype) external {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            loginsInBlock[msg.sender] = 0;
        }
        loginsInBlock[msg.sender]++;
        if (loginsInBlock[msg.sender] > MAX_LOGINS) revert WIM__TooManyRequests();

        require(tokens[msg.sender] == token, "token mismatch");
        emit LoggedIn(msg.sender, itype, WebIdentityModuleDefenseType.RateLimiting);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & CONTINUOUS MONITORING
//    • ✅ Defense: SignatureValidation – require signed auth payload  
//               ContinuousMonitoring – log anomalies
////////////////////////////////////////////////////////////////////////////////
contract WIMSafeAdvanced {
    address public signer;
    mapping(address => bytes32) public tokens;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public attempts;
    uint256 public constant MAX_ATTEMPTS = 5;

    event Registered(address indexed who, WebIdentityModuleType itype, WebIdentityModuleDefenseType defense);
    event LoggedIn(address indexed who, WebIdentityModuleType itype, WebIdentityModuleDefenseType defense);
    event Anomaly(address indexed who, string reason, WebIdentityModuleDefenseType defense);

    error WIM__TooManyRequests();
    error WIM__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function register(WebIdentityModuleType itype, bytes32 token, bytes calldata sig) external {
        // verify signature over (msg.sender||token||itype)
        bytes32 msgHash = keccak256(abi.encodePacked(msg.sender, token, itype));
        bytes32 ethMsg  = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8, bytes32, bytes32));
        if (ecrecover(ethMsg, v, r, s) != signer) revert WIM__InvalidSignature();
        tokens[msg.sender] = token;
        emit Registered(msg.sender, itype, WebIdentityModuleDefenseType.SignatureValidation);
    }

    function login(bytes32 token, WebIdentityModuleType itype) external {
        // rate-limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender] = block.number;
            attempts[msg.sender]   = 0;
        }
        attempts[msg.sender]++;
        if (attempts[msg.sender] > MAX_ATTEMPTS) {
            emit Anomaly(msg.sender, "excessive logins", WebIdentityModuleDefenseType.ContinuousMonitoring);
            revert WIM__TooManyRequests();
        }

        require(tokens[msg.sender] == token, "token mismatch");
        emit LoggedIn(msg.sender, itype, WebIdentityModuleDefenseType.ContinuousMonitoring);
    }
}
