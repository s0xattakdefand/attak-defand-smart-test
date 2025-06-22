// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title ZeroTrustKnowledgeSuite.sol
/// @notice On-chain analogues of “Zero Trust Knowledge” patterns:
///   Types: ExplicitKnowledge, ImplicitKnowledge, ContextualKnowledge  
///   AttackTypes: SocialEngineering, CredentialStuffing, InfoLeak  
///   DefenseTypes: KnowledgeValidation, BehaviorAnalytics, ConditionalAccess, ContinuousMonitoring  

enum ZeroTrustKnowledgeType        { ExplicitKnowledge, ImplicitKnowledge, ContextualKnowledge }
enum ZeroTrustKnowledgeAttackType  { SocialEngineering, CredentialStuffing, InfoLeak }
enum ZeroTrustKnowledgeDefenseType { KnowledgeValidation, BehaviorAnalytics, ConditionalAccess, ContinuousMonitoring }

error ZTK__NotAuthorized();
error ZTK__InvalidProof();
error ZTK__AnomalyDetected();
error ZTK__TooManyAttempts();
error ZTK__ConditionFailed();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE READER
//
//    • ❌ no checks: anyone may query stored “knowledge” → InfoLeak
////////////////////////////////////////////////////////////////////////////////
contract ZeroTrustKnowledgeVuln {
    // user → knowledge item → secret
    mapping(address => mapping(bytes32 => string)) public knowledge;
    event KnowledgeRevealed(
        address indexed who,
        bytes32           item,
        string            secret,
        ZeroTrustKnowledgeType    ktype,
        ZeroTrustKnowledgeAttackType attack
    );

    function storeKnowledge(bytes32 item, string calldata secret, ZeroTrustKnowledgeType ktype) external {
        knowledge[msg.sender][item] = secret;
    }

    function revealKnowledge(address user, bytes32 item, ZeroTrustKnowledgeType ktype) external {
        string memory secret = knowledge[user][item];
        emit KnowledgeRevealed(msg.sender, item, secret, ktype, ZeroTrustKnowledgeAttackType.InfoLeak);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//
//    • simulates credential stuffing & social engineering
////////////////////////////////////////////////////////////////////////////////
contract Attack_ZeroTrustKnowledge {
    ZeroTrustKnowledgeVuln public target;
    constructor(ZeroTrustKnowledgeVuln _t) { target = _t; }

    function phish(address victim, bytes32 item) external {
        target.revealKnowledge(victim, item, ZeroTrustKnowledgeType.ExplicitKnowledge);
    }

    function bruteForce(address victim, bytes32[] calldata items) external {
        for (uint i = 0; i < items.length; i++) {
            target.revealKnowledge(victim, items[i], ZeroTrustKnowledgeType.ImplicitKnowledge);
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH KNOWLEDGE VALIDATION
//
//    • ✅ Defense: KnowledgeValidation – require proof ≥ threshold
////////////////////////////////////////////////////////////////////////////////
contract ZeroTrustKnowledgeSafeValidation {
    mapping(address => mapping(bytes32 => string)) private knowledge;
    mapping(address => mapping(bytes32 => bytes32[])) public proofs; // [salt, hash(secret)]
    event KnowledgeRevealed(
        address indexed who,
        bytes32           item,
        ZeroTrustKnowledgeDefenseType defense
    );

    error ZTK__InvalidProof();

    function storeKnowledge(bytes32 item, string calldata secret) external {
        knowledge[msg.sender][item] = secret;
        proofs[msg.sender][item] = [keccak256(abi.encodePacked(secret)), keccak256(abi.encodePacked(msg.sender, item))];
    }

    /// must present correct hash(secret) and salt
    function revealKnowledge(
        address user,
        bytes32 item,
        bytes32 secretHash,
        bytes32 authHash
    ) external {
        bytes32[] storage p = proofs[user][item];
        if (p.length != 2
            || p[0] != secretHash
            || p[1] != authHash
            || authHash != keccak256(abi.encodePacked(user, item))
        ) revert ZTK__InvalidProof();
        emit KnowledgeRevealed(msg.sender, item, ZeroTrustKnowledgeDefenseType.KnowledgeValidation);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH BEHAVIOR ANALYTICS & RATE LIMIT
//
//    • ✅ Defense: BehaviorAnalytics – monitor anomalous query patterns  
//               RateLimit – cap reveals per block per caller
////////////////////////////////////////////////////////////////////////////////
contract ZeroTrustKnowledgeSafeBehavior {
    mapping(address => mapping(bytes32 => string)) private knowledge;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MAX_CALLS = 3;

    event KnowledgeRevealed(
        address indexed who,
        bytes32           item,
        ZeroTrustKnowledgeDefenseType defense
    );
    event AnomalyDetected(
        address indexed who,
        bytes32           item,
        string            reason,
        ZeroTrustKnowledgeDefenseType defense
    );

    error ZTK__TooManyAttempts();
    error ZTK__Anomaly();

    function storeKnowledge(bytes32 item, string calldata secret) external {
        knowledge[msg.sender][item] = secret;
    }

    function revealKnowledge(address user, bytes32 item) external {
        // rate-limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) {
            emit AnomalyDetected(msg.sender, item, "excessive queries", ZeroTrustKnowledgeDefenseType.BehaviorAnalytics);
            revert ZTK__TooManyAttempts();
        }
        // simplistic anomaly: if querying multiple users
        if (user != msg.sender) {
            emit AnomalyDetected(msg.sender, item, "cross-user access", ZeroTrustKnowledgeDefenseType.BehaviorAnalytics);
            revert ZTK__Anomaly();
        }
        emit KnowledgeRevealed(msg.sender, item, ZeroTrustKnowledgeDefenseType.BehaviorAnalytics);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH CONDITIONAL ACCESS & CONTINUOUS MONITORING
//
//    • ✅ Defense: ConditionalAccess – policies per item  
//               ContinuousMonitoring – audit all reveals
////////////////////////////////////////////////////////////////////////////////
contract ZeroTrustKnowledgeSafeAdvanced {
    mapping(address => mapping(bytes32 => string)) private knowledge;
    mapping(bytes32 => mapping(address => bool)) public policy; // item → user → allowed
    event KnowledgeRevealed(
        address indexed who,
        bytes32           item,
        ZeroTrustKnowledgeDefenseType defense
    );
    event AuditLog(
        address indexed who,
        bytes32           item,
        string            action,
        ZeroTrustKnowledgeDefenseType defense
    );

    error ZTK__ConditionFailed();

    function storeKnowledge(bytes32 item, string calldata secret) external {
        knowledge[msg.sender][item] = secret;
    }

    function setPolicy(bytes32 item, address user, bool ok) external {
        // item owner only
        require(knowledge[msg.sender][item].length > 0, "no such item");
        policy[item][user] = ok;
    }

    function revealKnowledge(address user, bytes32 item) external {
        if (!policy[item][msg.sender]) revert ZTK__ConditionFailed();
        emit AuditLog(msg.sender, item, "reveal", ZeroTrustKnowledgeDefenseType.ContinuousMonitoring);
        emit KnowledgeRevealed(msg.sender, item, ZeroTrustKnowledgeDefenseType.ConditionalAccess);
    }
}
