// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DataEncryptionStandardSecuritySuite.sol
/// @notice On‐chain analogues for “Data Encryption Standard (DES)” security patterns:
///   Types: SingleBlock, TripleDES, ECBMode, CBCMode  
///   AttackTypes: BruteForce, DifferentialCryptanalysis, LinearCryptanalysis, KeyRecovery  
///   DefenseTypes: StrongKeyEnforcement, RateLimit, HSMGuard, SignatureValidation, AuditLogging

enum DESType               { SingleBlock, TripleDES, ECBMode, CBCMode }
enum DESAttackType         { BruteForce, DifferentialCryptanalysis, LinearCryptanalysis, KeyRecovery }
enum DESDefenseType        { StrongKeyEnforcement, RateLimit, HSMGuard, SignatureValidation, AuditLogging }

error DES__WeakKey();
error DES__TooManyRequests();
error DES__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE DES STUB
//    • ❌ no key checks, no rate‐limit → trivial brute‐force
////////////////////////////////////////////////////////////////////////////////
contract DESVuln {
    mapping(bytes32 => bytes32) public encryptedData;

    event Encrypted(
        address indexed who,
        bytes32           plaintext,
        bytes32           ciphertext,
        DESType           dtype,
        DESAttackType     attack
    );

    /// @notice “Encrypt” by XORing with key (insecure stub)
    function encrypt(bytes32 plaintext, bytes8 key, DESType dtype) external {
        bytes32 ct = plaintext ^ bytes32(key);
        encryptedData[plaintext] = ct;
        emit Encrypted(msg.sender, plaintext, ct, dtype, DESAttackType.BruteForce);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates brute‐force key search & differential attacks
////////////////////////////////////////////////////////////////////////////////
contract Attack_DES {
    DESVuln public target;
    bytes32 public recovered;

    constructor(DESVuln _t) { target = _t; }

    /// @notice brute‐force all 2^8 keys (stubbed to 256 possibilities)
    function bruteForce(bytes32 pt) external {
        for (uint16 k = 0; k < 256; k++) {
            bytes8 key = bytes8(uint64(k));
            bytes32 ct = target.encryptedData(pt);
            if ((pt ^ bytes32(key)) == ct) {
                recovered = bytes32(key);
                break;
            }
        }
    }

    function differentialAttack(bytes32 pt1, bytes32 pt2) external {
        // stub: mark as performed
        recovered = pt1 ^ pt2;
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH STRONG‐KEY ENFORCEMENT
//    • ✅ Defense: StrongKeyEnforcement – require 56‐bit non‐weak keys
////////////////////////////////////////////////////////////////////////////////
contract DESSafeKeyCheck {
    mapping(bytes32 => bytes32) public encryptedData;

    event Encrypted(
        address indexed who,
        bytes32           plaintext,
        bytes32           ciphertext,
        DESType           dtype,
        DESDefenseType    defense
    );

    /// @notice disallow keys with low entropy
    function encrypt(bytes32 plaintext, bytes8 key, DESType dtype) external {
        // require at least half bits set
        uint pop = _popcount(uint64(bytes8(key)));
        if (pop < 28) revert DES__WeakKey();
        bytes32 ct = plaintext ^ bytes32(key);
        encryptedData[plaintext] = ct;
        emit Encrypted(msg.sender, plaintext, ct, dtype, DESDefenseType.StrongKeyEnforcement);
    }

    function _popcount(uint x) internal pure returns (uint) {
        uint count;
        while (x != 0) {
            count += x & 1;
            x >>= 1;
        }
        return count;
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH HSM‐GUARD & RATE LIMIT
//    • ✅ Defense: HSMGuard – simulate hardware module  
//               RateLimit – cap encrypts per block
////////////////////////////////////////////////////////////////////////////////
contract DESSafeHSM {
    mapping(bytes32 => bytes32) public encryptedData;
    mapping(address => uint)    public lastBlock;
    mapping(address => uint)    public callsInBlock;
    uint public constant MAX_CALLS = 5;

    event Encrypted(
        address indexed who,
        bytes32           plaintext,
        bytes32           ciphertext,
        DESType           dtype,
        DESDefenseType    defense
    );

    error DES__TooManyRequests();

    modifier rateLimit() {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender] = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert DES__TooManyRequests();
        _;
    }

    function encrypt(bytes32 plaintext, bytes8 key, DESType dtype)
        external
        rateLimit
    {
        // simulate HSM: off‐chain key use, here just stub
        bytes32 ct = keccak256(abi.encodePacked(plaintext, key, "HSM"));
        encryptedData[plaintext] = ct;
        emit Encrypted(msg.sender, plaintext, ct, dtype, DESDefenseType.HSMGuard);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & AUDIT LOGGING
//    • ✅ Defense: SignatureValidation – require admin‐signed params  
//               AuditLogging      – record each action
////////////////////////////////////////////////////////////////////////////////
contract DESSafeAdvanced {
    mapping(bytes32 => bytes32) public encryptedData;
    address public signer;

    event Encrypted(
        address indexed who,
        bytes32           plaintext,
        bytes32           ciphertext,
        DESType           dtype,
        DESDefenseType    defense
    );
    event AuditLog(
        address indexed who,
        bytes32           plaintext,
        DESType           dtype,
        DESDefenseType    defense
    );

    error DES__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function encrypt(
        bytes32 plaintext,
        bytes8 key,
        DESType dtype,
        bytes calldata sig
    ) external {
        // verify signature over (msg.sender||plaintext||key||dtype)
        bytes32 h = keccak256(abi.encodePacked(msg.sender, plaintext, key, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DES__InvalidSignature();

        bytes32 ct = keccak256(abi.encodePacked(plaintext, key));
        encryptedData[plaintext] = ct;
        emit Encrypted(msg.sender, plaintext, ct, dtype, DESDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, plaintext, dtype, DESDefenseType.AuditLogging);
    }
}
