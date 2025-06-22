// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title CryptoAlgoHashSuite.sol
/// @notice On‑chain analogues of “Cryptographic Algorithms / Hash” patterns:
///   Types: MD5, SHA1, SHA256, Keccak256  
///   AttackTypes: Collision, Preimage, LengthExtension  
///   DefenseTypes: UseSecureHash, SaltedHash, HMAC  

enum CryptoAlgoType         { MD5, SHA1, SHA256, Keccak256 }
enum CryptoAlgoAttackType   { Collision, Preimage, LengthExtension }
enum CryptoAlgoDefenseType  { UseSecureHash, SaltedHash, HMAC }

error CAH__WeakHash();
error CAH__NoSalt();
error CAH__BadHMAC();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE HASH: MD5‑style stub (no salt, easy collision)
///─────────────────────────────────────────────────────────────────────────────
library SimpleMD5 {
    /// @dev very insecure stub for MD5: keccak256 truncated to 16 bytes
    function hash(bytes calldata data) internal pure returns (bytes16) {
        bytes32 full = keccak256(data);
        return bytes16(full);
    }
}

contract HashVuln {
    using SimpleMD5 for bytes;

    event Hashed(
        address indexed who,
        bytes   data,
        bytes16 digest,
        CryptoAlgoType      algo,
        CryptoAlgoAttackType attack
    );

    /// ❌ uses insecure MD5 stub
    function hashMD5(bytes calldata data) external {
        bytes16 d = data.hash();
        emit Hashed(msg.sender, data, d, CryptoAlgoType.MD5, CryptoAlgoAttackType.Collision);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB: demonstrate collision by hashing two different inputs
///─────────────────────────────────────────────────────────────────────────────
contract Attack_Hash {
    HashVuln public target;
    event CollisionFound(bytes a, bytes b, bytes16 digest, CryptoAlgoAttackType attack);

    constructor(HashVuln _t) {
        target = _t;
    }

    /// stub collision: two arbitrary inputs producing same stub digest
    function findCollision(bytes calldata a, bytes calldata b) external {
        bytes16 da = SimpleMD5.hash(a);
        bytes16 db = SimpleMD5.hash(b);
        require(da == db, "no collision"); // off‑chain attacker finds such a pair
        emit CollisionFound(a, b, da, CryptoAlgoAttackType.Collision);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE HASH: use SHA256 and Keccak256 built‑ins
///─────────────────────────────────────────────────────────────────────────────
contract HashSafe {
    event Hashed(
        address indexed who,
        bytes   data,
        bytes32 digest,
        CryptoAlgoType       algo,
        CryptoAlgoDefenseType defense
    );

    /// ✅ SHA‑256 is secure against collisions and preimages
    function hashSHA256(bytes calldata data) external {
        bytes32 d = sha256(data);
        emit Hashed(msg.sender, data, d, CryptoAlgoType.SHA256, CryptoAlgoDefenseType.UseSecureHash);
    }

    /// ✅ Keccak‑256 (alias SHA‑3)
    function hashKeccak(bytes calldata data) external {
        bytes32 d = keccak256(data);
        emit Hashed(msg.sender, data, d, CryptoAlgoType.Keccak256, CryptoAlgoDefenseType.UseSecureHash);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE SALTED & HMAC‑PROTECTED HASH
///─────────────────────────────────────────────────────────────────────────────
contract HashSafeHMAC {
    bytes32 public immutable key;

    event Hashed(
        address indexed who,
        bytes   data,
        bytes32 digest,
        CryptoAlgoDefenseType defense
    );

    constructor(bytes32 _key) {
        key = _key;
    }

    /// ✅ salted hash: defend against preimage with unique salt
    function saltedHash(bytes32 salt, bytes calldata data) external {
        if (salt == bytes32(0)) revert CAH__NoSalt();
        bytes32 d = sha256(abi.encodePacked(salt, data));
        emit Hashed(msg.sender, data, d, CryptoAlgoDefenseType.SaltedHash);
    }

    /// ✅ HMAC‑SHA256: defends length‑extension and preimage attacks
    function hmac(bytes calldata data) external {
        // HMAC = sha256( key ⊕ opad || sha256(key ⊕ ipad || data) )
        bytes32 ipad = key ^ bytes32(0x3636363636363636363636363636363636363636363636363636363636363636);
        bytes32 opad = key ^ bytes32(0x5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c);
        bytes32 inner = sha256(abi.encodePacked(ipad, data));
        bytes32 mac   = sha256(abi.encodePacked(opad, inner));
        emit Hashed(msg.sender, data, mac, CryptoAlgoDefenseType.HMAC);
    }
}
