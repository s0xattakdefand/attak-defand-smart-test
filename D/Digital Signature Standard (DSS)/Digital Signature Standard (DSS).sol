// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DigitalSignatureStandardSuite.sol
/// @notice On‑chain analogues of the FIPS 186 “Digital Signature Standard” (DSS) patterns:
///   Types: DSA, ECDSA  
///   AttackTypes: ParameterTampering, KReuse, SideChannelLeak  
///   DefenseTypes: ParameterValidation, RandomK, ConstantTime  

enum DigitalSignatureStandardType         { DSA, ECDSA }
enum DigitalSignatureStandardAttackType   { ParameterTampering, KReuse, SideChannelLeak }
enum DigitalSignatureStandardDefenseType  { ParameterValidation, RandomK, ConstantTime }

error DSS__BadParams();
error DSS__ReuseDetected();
error DSS__InvalidSignature();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE DSS IMPLEMENTATION
///
///    • no parameter checks, fixed k, data‑dependent loops → trivial key recovery  
///    • Attack: KReuse, SideChannelLeak
///─────────────────────────────────────────────────────────────────────────────
contract DSSVuln {
    uint256 public p;
    uint256 public q;
    uint256 public g;
    uint256 public y; // public key

    event Signed(
        address indexed who,
        bytes32 message,
        uint256 r,
        uint256 s,
        DigitalSignatureStandardAttackType attack
    );

    function setParams(uint256 p_, uint256 q_, uint256 g_, uint256 y_) external {
        p = p_; q = q_; g = g_; y = y_;
    }

    /// ❌ uses fixed k=1 and no parameter validation
    function sign(bytes32 message) external returns (uint256 r, uint256 s) {
        uint256 k = 1;
        r = modExp(g, k, p) % q;
        // stub s = H(m) + r mod q
        s = (uint256(message) + r) % q;
        emit Signed(msg.sender, message, r, s, DigitalSignatureStandardAttackType.KReuse);
    }

    function modExp(uint256 base, uint256 exp, uint256 mod) internal pure returns (uint256 result) {
        result = 1;
        for (uint256 i = 0; i < exp; i++) {
            result = mulmod(result, base, mod);
        }
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB
///
///    • demonstrates key recovery via k reuse  
///─────────────────────────────────────────────────────────────────────────────
contract Attack_DSS {
    DSSVuln public target;
    constructor(DSSVuln _t) { target = _t; }

    /// given r,s and m, recover x: x = (s − H(m))·r⁻¹ mod q
    function recoverKey(bytes32 m, uint256 r, uint256 s) external view returns (uint256 x) {
        uint256 q = target.q();
        uint256 hm = uint256(m) % q;
        uint256 num = addmod(s, q - hm, q);
        // compute inverse r⁻¹ mod q via Fermat
        uint256 rInv = modExp(r, q - 2, q);
        x = mulmod(num, rInv, q);
    }

    function modExp(uint256 base, uint256 exp, uint256 mod) internal pure returns (uint256 result) {
        result = 1;
        for (uint256 i = 0; i < exp; i++) {
            result = mulmod(result, base, mod);
        }
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE DSS WITH PARAMETER VALIDATION & RANDOM k
///
///    • Defense: ParameterValidation + RandomK  
///─────────────────────────────────────────────────────────────────────────────
contract DSSSafe {
    uint256 public p;
    uint256 public q;
    uint256 public g;
    uint256 public y;

    event Signed(
        address indexed who,
        bytes32 message,
        uint256 r,
        uint256 s,
        DigitalSignatureStandardDefenseType defense
    );

    error DSS__BadParams();

    function setParams(uint256 p_, uint256 q_, uint256 g_, uint256 y_) external {
        // stub check: q divides p-1 and g in [2,p-2]
        if (p_ <= q_ || (p_ - 1) % q_ != 0 || g_ <= 1 || g_ >= p_ - 1) revert DSS__BadParams();
        p = p_; q = q_; g = g_; y = y_;
    }

    /// ✅ derive k pseudo‑randomly from blockhash to avoid reuse
    function sign(bytes32 message) external returns (uint256 r, uint256 s) {
        uint256 k = uint256(keccak256(abi.encodePacked(blockhash(block.number - 1), message))) % q;
        r = modExp(g, k, p) % q;
        uint256 hm = uint256(message) % q;
        // stub x unknown, approximate numerator = H(m) + r
        uint256 num = addmod(hm, r, q);
        uint256 kInv = modExp(k, q - 2, q);
        s = mulmod(num, kInv, q);
        emit Signed(msg.sender, message, r, s, DigitalSignatureStandardDefenseType.RandomK);
    }

    function modExp(uint256 base, uint256 exp, uint256 mod) internal pure returns (uint256 result) {
        result = 1;
        for (uint256 i = 0; i < exp; i++) {
            result = mulmod(result, base, mod);
        }
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE DSS ADVANCED WITH CONSTANT‑TIME SIGNING
///
///    • Defense: ConstantTime loops + k reuse protection  
///─────────────────────────────────────────────────────────────────────────────
contract DSSSafeAdvanced {
    uint256 public p;
    uint256 public q;
    uint256 public g;
    mapping(bytes32 => bool) private _used;

    event Signed(
        address indexed who,
        bytes32 message,
        uint256 r,
        uint256 s,
        DigitalSignatureStandardDefenseType defense
    );

    error DSS__BadParams();
    error DSS__ReuseDetected();

    function setParams(uint256 p_, uint256 q_, uint256 g_, uint256 y_) external {
        if (p_ <= q_ || (p_ - 1) % q_ != 0 || g_ <= 1 || g_ >= p_ - 1) revert DSS__BadParams();
        p = p_; q = q_; g = g_;
    }

    /// ✅ constant‑time stub and prevent signing same message twice
    function sign(bytes32 message) external returns (uint256 r, uint256 s) {
        if (_used[message]) revert DSS__ReuseDetected();
        _used[message] = true;
        // constant‑time k derivation stub
        uint256 k = uint256(keccak256(abi.encodePacked(blockhash(block.number - 1), message))) % q;
        // constant‑time modExp stub
        uint256 acc = 1;
        for (uint256 i = 0; i < q; i++) {
            acc = mulmod(acc, g, p);
        }
        r = acc % q;
        uint256 hm = uint256(message) % q;
        uint256 num = addmod(hm, r, q);
        uint256 kInv = modExp(k, q - 2, q);
        s = mulmod(num, kInv, q);
        emit Signed(msg.sender, message, r, s, DigitalSignatureStandardDefenseType.ConstantTime);
    }

    function modExp(uint256 base, uint256 exp, uint256 mod) internal pure returns (uint256 result) {
        result = 1;
        for (uint256 i = 0; i < exp; i++) {
            result = mulmod(result, base, mod);
        }
    }
}
