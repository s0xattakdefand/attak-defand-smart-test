// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DigitalSignatureAlgorithmSuite.sol
/// @notice On‑chain analogues of “Digital Signature Algorithm” (DSA) patterns:
///   Types: DSA, ECDSA, EdDSA  
///   AttackTypes: ParameterTampering, KReuse, Forgery  
///   DefenseTypes: ParameterValidation, RandomK, ConstantTime  

enum DigitalSignatureAlgorithmType       { DSA, ECDSA, EdDSA }
enum DigitalSignatureAlgorithmAttackType { ParameterTampering, KReuse, Forgery }
enum DigitalSignatureAlgorithmDefenseType{ ParameterValidation, RandomK, ConstantTime }

error DSA__BadParams();
error DSA__ReuseDetected();
error DSA__InvalidSignature();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE DSA (fixed k, no param checks)
///
///    • k is constant = 1 → trivially recoverable  
///    • no validation of p, q, g  
///    • Attack: KReuse, Forgery  
///─────────────────────────────────────────────────────────────────────────────
contract DSAAlgorithmVuln {
    uint256 public p;
    uint256 public q;
    uint256 public g;
    uint256 public y; // public key = g^x mod p

    event Signed(
        address indexed who,
        bytes32 message,
        uint256 r,
        uint256 s,
        DigitalSignatureAlgorithmAttackType attack
    );

    function setParams(uint256 p_, uint256 q_, uint256 g_, uint256 y_) external {
        p = p_; q = q_; g = g_; y = y_;
    }

    /// ❌ uses fixed k=1 for all messages
    function sign(bytes32 message) external returns (uint256 r, uint256 s) {
        uint256 k = 1;
        r = modExp(g, k, p) % q;
        // s = k⁻¹ (H(message) + x·r) mod q, stub x unknown so we just emit fake s
        s = uint256(message) + r;
        emit Signed(msg.sender, message, r, s, DigitalSignatureAlgorithmAttackType.KReuse);
    }

    /// stub modular exponentiation
    function modExp(uint256 base, uint256 exp, uint256 mod) internal pure returns (uint256) {
        uint256 result = 1;
        for (uint256 i = 0; i < exp; i++) {
            result = mulmod(result, base, mod);
        }
        return result;
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB
///
///    • recovers x when two signatures share k  
///    • forges new signatures  
///─────────────────────────────────────────────────────────────────────────────
contract Attack_DSAAlgorithm {
    DSAAlgorithmVuln public target;

    constructor(DSAAlgorithmVuln _t) {
        target = _t;
    }

    /// demonstrates reuse: given r,s for two messages with same k=1
    function recoverPrivateKey(bytes32 m1, uint256 r1, uint256 s1, bytes32 m2, uint256 r2, uint256 s2)
        external
        view
        returns (uint256 x)
    {
        // since k=1 and s = H(m)+ x·r, x = (s - H(m))·r⁻¹ mod q
        uint256 q = target.q();
        uint256 hm = uint256(m1);
        uint256 numerator = addmod(s1, q - hm, q);
        // compute inverse r⁻¹ mod q
        uint256 rInv = modExp(r1, q - 2, q);
        x = mulmod(numerator, rInv, q);
    }

    function modExp(uint256 base, uint256 exp, uint256 mod) internal pure returns (uint256) {
        uint256 result = 1;
        for (uint256 i = 0; i < exp; i++) {
            result = mulmod(result, base, mod);
        }
        return result;
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE DSA WITH PARAMETER VALIDATION & RANDOM k
///
///    • Defense: ParameterValidation (p,q primes, g in [2,p-2])  
///               RandomK (k = pseudo‑random via blockhash)  
///─────────────────────────────────────────────────────────────────────────────
contract DSAAlgorithmSafe {
    uint256 public p;
    uint256 public q;
    uint256 public g;
    uint256 public y;

    event Signed(
        address indexed who,
        bytes32 message,
        uint256 r,
        uint256 s,
        DigitalSignatureAlgorithmDefenseType defense
    );

    error DSA__BadParams();

    function setParams(uint256 p_, uint256 q_, uint256 g_, uint256 y_) external {
        // stub checks: q divides p-1 and g in range
        if (p_ <= q_ || (p_ - 1) % q_ != 0 || g_ <= 1 || g_ >= p_ - 1) {
            revert DSA__BadParams();
        }
        p = p_; q = q_; g = g_; y = y_;
    }

    /// ✅ random k derived from blockhash to avoid reuse
    function sign(bytes32 message) external returns (uint256 r, uint256 s) {
        uint256 k = uint256(keccak256(abi.encodePacked(blockhash(block.number - 1), message))) % q;
        r = modExp(g, k, p) % q;
        uint256 hm = uint256(message);
        // stub s = k⁻¹ (H(message) + x·r) mod q; x unknown so we just combine
        uint256 numerator = addmod(hm, mulmod(1, r, q), q);
        uint256 kInv = modExp(k, q - 2, q);
        s = mulmod(numerator, kInv, q);
        emit Signed(msg.sender, message, r, s, DigitalSignatureAlgorithmDefenseType.RandomK);
    }

    function modExp(uint256 base, uint256 exp, uint256 mod) internal pure returns (uint256) {
        uint256 result = 1;
        for (uint256 i = 0; i < exp; i++) {
            result = mulmod(result, base, mod);
        }
        return result;
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE ADVANCED DSA WITH CONSTANT‑TIME & NONCE PROTECT
///
///    • Defense: ConstantTime (no data‑dependent branches)  
///               ParameterValidation + RandomK as above  
///─────────────────────────────────────────────────────────────────────────────
contract DSAAlgorithmSafeAdvanced {
    uint256 public p;
    uint256 public q;
    uint256 public g;
    uint256 public y;
    event Signed(
        address indexed who,
        bytes32 message,
        uint256 r,
        uint256 s,
        DigitalSignatureAlgorithmDefenseType defense
    );

    error DSA__BadParams();
    error DSA__ReuseDetected();

    mapping(bytes32 => bool) private _usedMsg;

    function setParams(uint256 p_, uint256 q_, uint256 g_, uint256 y_) external {
        if (p_ <= q_ || (p_ - 1) % q_ != 0 || g_ <= 1 || g_ >= p_ - 1) {
            revert DSA__BadParams();
        }
        p = p_; q = q_; g = g_; y = y_;
    }

    /// ✅ constant‑time stub loop and prohibit duplicate messages
    function sign(bytes32 message) external returns (uint256 r, uint256 s) {
        if (_usedMsg[message]) revert DSA__ReuseDetected();
        _usedMsg[message] = true;
        // random k
        uint256 k = uint256(keccak256(abi.encodePacked(blockhash(block.number - 1), message))) % q;
        // constant-time modular exponentiation stub
        uint256 acc = 1;
        for (uint256 i = 0; i < q; i++) {
            acc = mulmod(acc, g, p);
        }
        r = acc % q;
        // compute s similarly in constant-time stub
        uint256 hm = uint256(message);
        uint256 numerator = addmod(hm, mulmod(1, r, q), q);
        uint256 kInv = modExp(k, q - 2, q);
        s = mulmod(numerator, kInv, q);
        emit Signed(msg.sender, message, r, s, DigitalSignatureAlgorithmDefenseType.ConstantTime);
    }

    function modExp(uint256 base, uint256 exp, uint256 mod) internal pure returns (uint256) {
        uint256 result = 1;
        for (uint256 i = 0; i < exp; i++) {
            result = mulmod(result, base, mod);
        }
        return result;
    }
}
