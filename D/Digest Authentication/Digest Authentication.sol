// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DigestAuthSuite.sol
/// @notice On‑chain analogues of “HTTP Digest Authentication” patterns:
///   Types: MD5, MD5sess, SHA256, SHA256sess  
///   AttackTypes: Replay, BruteForce, FakeNonce, StaleNonce  
///   DefenseTypes: NonceValidation, QopEnforced, RateLimit, NonceExpiration  

enum DigestAuthType         { MD5, MD5sess, SHA256, SHA256sess }
enum DigestAuthAttackType   { Replay, BruteForce, FakeNonce, StaleNonce }
enum DigestAuthDefenseType  { NonceValidation, QopEnforced, RateLimit, NonceExpiration }

error DA__InvalidNonce();
error DA__TooManyRequests();
error DA__StaleNonce();
error DA__BadQop();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE DIGEST AUTH (no nonce or qop checks)
///
///    • accepts any response as valid  
///    • Attack: Replay
///─────────────────────────────────────────────────────────────────────────────
contract DigestAuthVuln {
    event AuthResult(
        address indexed who,
        string   user,
        bool     success,
        DigestAuthAttackType attack
    );

    /// ❌ no nonce/qop validation: always succeed
    function authenticate(
        string calldata user,
        string calldata realm,
        string calldata nonce,
        string calldata uri,
        bytes32        response
    ) external {
        emit AuthResult(msg.sender, user, true, DigestAuthAttackType.Replay);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB (replay & brute‑force)
///
///    • Replay: resubmit captured response  
///    • BruteForce: try many response guesses
///─────────────────────────────────────────────────────────────────────────────
contract Attack_DigestAuth {
    DigestAuthVuln public target;
    constructor(DigestAuthVuln _t) { target = _t; }

    /// replay a previously valid response
    function replay(
        string calldata user,
        string calldata realm,
        string calldata nonce,
        string calldata uri,
        bytes32        resp
    ) external {
        target.authenticate(user, realm, nonce, uri, resp);
    }

    /// brute‑force by trying multiple nonces/uris
    function brute(
        string calldata user,
        string calldata realm,
        string[] calldata nonces,
        string[] calldata uris,
        bytes32[] calldata guesses
    ) external {
        for (uint i = 0; i < nonces.length; i++) {
            for (uint j = 0; j < uris.length; j++) {
                target.authenticate(user, realm, nonces[i], uris[j], guesses[(i+ j) % guesses.length]);
            }
        }
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE AUTH WITH NONCE VALIDATION & QOP ENFORCEMENT
///
///    • Defense: NonceValidation – prevent replay  
///               QopEnforced – require “auth” qop
///─────────────────────────────────────────────────────────────────────────────
contract DigestAuthSafe {
    mapping(string => mapping(bytes32 => bool)) public usedNonce;
    event AuthResult(
        address indexed who,
        string   user,
        bool     success,
        DigestAuthDefenseType defense
    );

    /// ✅ require nonce unused and qop=="auth"
    function authenticate(
        string calldata user,
        string calldata realm,
        string calldata nonce,
        string calldata uri,
        string calldata qop,
        bytes32        response
    ) external {
        if (usedNonce[user][keccak256(abi.encodePacked(nonce))]) revert DA__InvalidNonce();
        usedNonce[user][keccak256(abi.encodePacked(nonce))] = true;
        if (keccak256(bytes(qop)) != keccak256(bytes("auth"))) revert DA__BadQop();
        // stub validate response off‑chain
        emit AuthResult(msg.sender, user, true, DigestAuthDefenseType.NonceValidation);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) ADVANCED SAFE WITH RATE‑LIMIT & NONCE EXPIRATION
///
///    • Defense: RateLimit – cap auth attempts per block  
///               NonceExpiration – reject old nonces
///─────────────────────────────────────────────────────────────────────────────
contract DigestAuthSafeAdvanced {
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public attemptsInBlock;
    mapping(string  => mapping(bytes32 => uint256)) public nonceTimestamp;
    uint256 public constant MAX_PER_BLOCK = 5;
    uint256 public constant NONCE_LIFETIME = 5 minutes;

    event AuthResult(
        address indexed who,
        string   user,
        bool     success,
        DigestAuthDefenseType defense
    );

    error DA__TooManyRequests();
    error DA__StaleNonce();

    /// ✅ rate‑limit auth calls and require fresh nonce
    function authenticate(
        string calldata user,
        string calldata realm,
        string calldata nonce,
        string calldata uri,
        string calldata qop,
        uint256       nonceTs,
        bytes32       response
    ) external {
        // rate‑limit per caller
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]     = block.number;
            attemptsInBlock[msg.sender] = 0;
        }
        attemptsInBlock[msg.sender]++;
        if (attemptsInBlock[msg.sender] > MAX_PER_BLOCK) revert DA__TooManyRequests();

        // nonce freshness
        if (block.timestamp > nonceTs + NONCE_LIFETIME) revert DA__StaleNonce();
        bytes32 nkey = keccak256(abi.encodePacked(nonce));
        require(nonceTimestamp[user][nkey] == 0, "replay");
        nonceTimestamp[user][nkey] = nonceTs;

        // stub qop & response validation off‑chain
        emit AuthResult(msg.sender, user, true, DigestAuthDefenseType.NonceExpiration);
    }
}
