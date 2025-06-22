// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DigitalEnvelopeSuite.sol
/// @notice On‑chain analogues of “Digital Envelope” patterns:
///   Types: Symmetric, Asymmetric, Hybrid  
///   AttackTypes: KeyExposure, Forgery, Replay  
///   DefenseTypes: SecureKeyStorage, IntegrityCheck, EphemeralKeys, NonceProtect  

enum DigitalEnvelopeType        { Symmetric, Asymmetric, Hybrid }
enum DigitalEnvelopeAttackType  { KeyExposure, Forgery, Replay }
enum DigitalEnvelopeDefenseType { SecureKeyStorage, IntegrityCheck, EphemeralKeys, NonceProtect }

error DE__NoKey();
error DE__BadIntegrity();
error DE__ReplayDetected();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE ENVELOPE (no integrity, key stored in‐clear)
///
///    • no integrity or replay protection → forgery & key exposure  
///    • Attack: KeyExposure, Forgery, Replay
///─────────────────────────────────────────────────────────────────────────────
contract EnvelopeVuln {
    struct Envelope { bytes ciphertext; bytes key; }
    mapping(uint256 => Envelope) public envelopes;

    event EnvelopeCreated(
        address indexed who,
        uint256 indexed id,
        bytes        ciphertext,
        DigitalEnvelopeAttackType attack
    );
    event EnvelopeOpened(
        address indexed who,
        uint256 indexed id,
        bytes        plaintext,
        DigitalEnvelopeAttackType attack
    );

    /// ❌ store ciphertext + key with no integrity or secrecy
    function create(uint256 id, bytes calldata plaintext, bytes calldata key) external {
        // stub “encryption”: XOR with keccak(key)
        bytes32 mask = keccak256(key);
        bytes memory ct = new bytes(plaintext.length);
        for (uint i = 0; i < plaintext.length; i++) {
            ct[i] = plaintext[i] ^ mask[i % 32];
        }
        envelopes[id] = Envelope(ct, key);
        emit EnvelopeCreated(msg.sender, id, ct, DigitalEnvelopeAttackType.KeyExposure);
    }

    /// ❌ anyone can unwrap and get plaintext
    function open(uint256 id) external view returns (bytes memory) {
        Envelope storage env = envelopes[id];
        bytes32 mask = keccak256(env.key);
        bytes memory pt = new bytes(env.ciphertext.length);
        for (uint i = 0; i < env.ciphertext.length; i++) {
            pt[i] = env.ciphertext[i] ^ mask[i % 32];
        }
        emit EnvelopeOpened(msg.sender, id, pt, DigitalEnvelopeAttackType.Replay);
        return pt;
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB
///
///    • attacker replays or inspects key to forge envelopes
///─────────────────────────────────────────────────────────────────────────────
contract Attack_Envelope {
    EnvelopeVuln public target;
    constructor(EnvelopeVuln _t) { target = _t; }

    function extractKey(uint256 id) external view returns (bytes memory) {
        // simulate key exposure by reading storage
        return target.envelopes(id).key;
    }

    function replayOpen(uint256 id) external view returns (bytes memory) {
        return target.open(id);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE ENVELOPE WITH INTEGRITY (HMAC) & SECURE KEY STORAGE
///
///    • Defense: IntegrityCheck (HMAC) + SecureKeyStorage (key private)
///─────────────────────────────────────────────────────────────────────────────
contract EnvelopeSafeIntegrity {
    struct Envelope { bytes ciphertext; bytes32 hmac; }
    mapping(uint256 => Envelope) private envelopes;
    mapping(uint256 => bytes)    private keys;
    event EnvelopeCreated(
        address indexed who,
        uint256 indexed id,
        DigitalEnvelopeDefenseType defense
    );
    event EnvelopeOpened(
        address indexed who,
        uint256 indexed id,
        bytes        plaintext,
        DigitalEnvelopeDefenseType defense
    );

    /// owner stores key privately
    address public owner;
    constructor() { owner = msg.sender; }

    function create(uint256 id, bytes calldata plaintext, bytes calldata key) external {
        require(msg.sender == owner, "only owner");
        // stub “encryption”
        bytes32 mask = keccak256(key);
        bytes memory ct = new bytes(plaintext.length);
        for (uint i = 0; i < plaintext.length; i++) {
            ct[i] = plaintext[i] ^ mask[i % 32];
        }
        // compute HMAC = keccak(ct || key)
        bytes32 h = keccak256(abi.encodePacked(ct, key));
        envelopes[id] = Envelope(ct, h);
        keys[id] = key;
        emit EnvelopeCreated(msg.sender, id, DigitalEnvelopeDefenseType.IntegrityCheck);
    }

    function open(uint256 id) external view returns (bytes memory) {
        Envelope storage env = envelopes[id];
        bytes storage key = keys[id];
        // verify HMAC
        bytes32 expected = keccak256(abi.encodePacked(env.ciphertext, key));
        if (expected != env.hmac) revert DE__BadIntegrity();
        // decrypt
        bytes32 mask = keccak256(key);
        bytes memory pt = new bytes(env.ciphertext.length);
        for (uint i = 0; i < env.ciphertext.length; i++) {
            pt[i] = env.ciphertext[i] ^ mask[i % 32];
        }
        emit EnvelopeOpened(msg.sender, id, pt, DigitalEnvelopeDefenseType.IntegrityCheck);
        return pt;
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE ADVANCED ENVELOPE WITH EPHEMERAL KEYS & NONCE PROTECTION
///
///    • Defense: EphemeralKeys + NonceProtect (prevent replay)
///─────────────────────────────────────────────────────────────────────────────
contract EnvelopeSafeAdvanced {
    struct Envelope { bytes ciphertext; bytes32 hmac; uint256 nonce; }
    mapping(uint256 => Envelope) public envelopes;
    mapping(uint256 => bool)    public seenNonce;
    address public owner;
    event EnvelopeCreated(
        address indexed who,
        uint256 indexed id,
        DigitalEnvelopeDefenseType defense
    );
    event EnvelopeOpened(
        address indexed who,
        uint256 indexed id,
        bytes        plaintext,
        DigitalEnvelopeDefenseType defense
    );

    constructor() { owner = msg.sender; }

    /// uses ephemeral symmetric key per envelope
    function create(
        uint256 id,
        bytes calldata plaintext,
        bytes32 ephemeralKey,
        uint256 nonce
    ) external {
        require(msg.sender == owner, "only owner");
        require(!seenNonce[nonce], "replay nonce");
        seenNonce[nonce] = true;
        // encrypt stub
        bytes memory ct = new bytes(plaintext.length);
        for (uint i = 0; i < plaintext.length; i++) {
            ct[i] = plaintext[i] ^ ephemeralKey[i % 32];
        }
        // HMAC = keccak(ct || ephemeralKey || nonce)
        bytes32 h = keccak256(abi.encodePacked(ct, ephemeralKey, nonce));
        envelopes[id] = Envelope(ct, h, nonce);
        emit EnvelopeCreated(msg.sender, id, DigitalEnvelopeDefenseType.EphemeralKeys);
    }

    function open(uint256 id, bytes32 ephemeralKey) external view returns (bytes memory) {
        Envelope storage env = envelopes[id];
        // verify HMAC
        bytes32 expected = keccak256(abi.encodePacked(env.ciphertext, ephemeralKey, env.nonce));
        if (expected != env.hmac) revert DE__BadIntegrity();
        // decrypt
        bytes memory pt = new bytes(env.ciphertext.length);
        for (uint i = 0; i < env.ciphertext.length; i++) {
            pt[i] = env.ciphertext[i] ^ ephemeralKey[i % 32];
        }
        emit EnvelopeOpened(msg.sender, id, pt, DigitalEnvelopeDefenseType.NonceProtect);
        return pt;
    }
}
