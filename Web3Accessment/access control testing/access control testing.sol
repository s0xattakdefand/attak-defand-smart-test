// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AccessControlTestingSuite.sol
/// @notice On‐chain analogues of “Access Control Testing” patterns:
///   Types: ManualTesting, AutomatedTesting, RoleBasedTesting, PolicyTesting  
///   AttackTypes: PrivilegeEscalation, UnauthorizedAccess, DataTampering, Bypass  
///   DefenseTypes: AccessControl, Logging, RateLimit, SignatureValidation, AuditLogging

enum ACTType              { ManualTesting, AutomatedTesting, RoleBasedTesting, PolicyTesting }
enum ACTAttackType        { PrivilegeEscalation, UnauthorizedAccess, DataTampering, Bypass }
enum ACTDefenseType       { AccessControl, Logging, RateLimit, SignatureValidation, AuditLogging }

error ACT__NotAuthorized();
error ACT__TooManyRequests();
error ACT__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE VAULT
//    • ❌ no checks: anyone may set or get secrets → UnauthorizedAccess
////////////////////////////////////////////////////////////////////////////////
contract ACTVuln {
    mapping(address => string) public secrets;

    event SecretSet(address indexed who, address indexed user, string secret, ACTType dtype, ACTAttackType attack);
    event SecretGot(address indexed who, address indexed user, string secret, ACTType dtype, ACTAttackType attack);

    function setSecret(address user, string calldata secret) external {
        secrets[user] = secret;
        emit SecretSet(msg.sender, user, secret, ACTType.ManualTesting, ACTAttackType.PrivilegeEscalation);
    }

    function getSecret(address user) external view returns (string memory) {
        string memory s = secrets[user];
        emit SecretGot(msg.sender, user, s, ACTType.ManualTesting, ACTAttackType.UnauthorizedAccess);
        return s;
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates unauthorized set/get, tampering, bypass
////////////////////////////////////////////////////////////////////////////////
contract Attack_ACT {
    ACTVuln public target;
    address public victim;
    string  public lastSecret;

    constructor(ACTVuln _t, address _victim) {
        target = _t;
        victim = _victim;
    }

    function tamperSecret(string calldata fake) external {
        target.setSecret(victim, fake);
        lastSecret = fake;
    }

    function leakSecret() external {
        lastSecret = target.getSecret(victim);
    }

    function replayTamper() external {
        target.setSecret(victim, lastSecret);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may set/get
////////////////////////////////////////////////////////////////////////////////
contract ACTSafeAccess {
    mapping(address => string) public secrets;
    address public owner;

    event SecretSet(address indexed who, address indexed user, ACTType dtype, ACTDefenseType defense);
    event SecretGot(address indexed who, address indexed user, ACTType dtype, ACTDefenseType defense);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert ACT__NotAuthorized();
        _;
    }

    function setSecret(address user, string calldata secret) external onlyOwner {
        secrets[user] = secret;
        emit SecretSet(msg.sender, user, ACTType.PolicyTesting, ACTDefenseType.AccessControl);
    }

    function getSecret(address user) external view onlyOwner returns (string memory) {
        emit SecretGot(msg.sender, user, ACTType.PolicyTesting, ACTDefenseType.AccessControl);
        return secrets[user];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH LOGGING & RATE LIMIT
//    • ✅ Defense: Logging – record every op  
//               RateLimit – cap sets per block
////////////////////////////////////////////////////////////////////////////////
contract ACTSafeRateLimit {
    mapping(address => string) public secrets;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public setsInBlock;
    uint256 public constant MAX_SETS = 3;

    event SecretSet(address indexed who, address indexed user, ACTType dtype, ACTDefenseType defense);
    event SecretGot(address indexed who, address indexed user, ACTType dtype, ACTDefenseType defense);

    error ACT__TooManyRequests();

    function setSecret(address user, string calldata secret) external {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]   = block.number;
            setsInBlock[msg.sender] = 0;
        }
        setsInBlock[msg.sender]++;
        if (setsInBlock[msg.sender] > MAX_SETS) revert ACT__TooManyRequests();

        secrets[user] = secret;
        emit SecretSet(msg.sender, user, ACTType.RoleBasedTesting, ACTDefenseType.RateLimit);
    }

    function getSecret(address user) external view returns (string memory) {
        emit SecretGot(msg.sender, user, ACTType.RoleBasedTesting, ACTDefenseType.Logging);
        return secrets[user];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & AUDIT LOGGING
//    • ✅ Defense: SignatureValidation – require off‐chain signed set  
//               AuditLogging         – record every operation
////////////////////////////////////////////////////////////////////////////////
contract ACTSafeAdvanced {
    mapping(address => string) public secrets;
    address public signer;

    event SecretSet(address indexed who, address indexed user, ACTType dtype, ACTDefenseType defense);
    event SecretGot(address indexed who, address indexed user, ACTType dtype, ACTDefenseType defense);
    event AuditLog(address indexed who, string action, address indexed user, ACTDefenseType defense);

    error ACT__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function setSecret(
        address user,
        string calldata secret,
        bytes calldata sig
    ) external {
        // verify signature over (user||secret)
        bytes32 h = keccak256(abi.encodePacked(user, secret));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert ACT__InvalidSignature();

        secrets[user] = secret;
        emit SecretSet(msg.sender, user, ACTType.AutomatedTesting, ACTDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "setSecret", user, ACTDefenseType.AuditLogging);
    }

    function getSecret(
        address user,
        bytes calldata sig
    ) external view returns (string memory) {
        // verify signature over (msg.sender||user)
        bytes32 h = keccak256(abi.encodePacked(msg.sender, user));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert ACT__InvalidSignature();

        emit SecretGot(msg.sender, user, ACTType.AutomatedTesting, ACTDefenseType.AuditLogging);
        emit AuditLog(msg.sender, "getSecret", user, ACTDefenseType.AuditLogging);
        return secrets[user];
    }
}
