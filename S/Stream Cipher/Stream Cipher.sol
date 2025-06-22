// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title StreamCipherSuite.sol
/// @notice Four “stream cipher” patterns with common pitfalls and hardened defenses:
///   1) Keystream Reuse  
///   2) Hard‑Coded Key  
///   3) Predictable Nonce  
///   4) Missing Authentication (MAC)  

error Stream__NonceReuse();
error Stream__Unauthorized();
error Stream__PredictableNonce();
error Stream__InvalidMac();

////////////////////////////////////////////////////////////////////////////////
// ──────── Shared Libraries ──────────────────────────────────────────────────
////////////////////////////////////////////////////////////////////////////////

library StreamCipher {
    /// @dev simple keccak‑based keystream: block = keccak256(key∥nonce∥ctr)
    function encrypt(
        bytes32    key,
        uint256    nonce,
        bytes calldata data
    ) internal pure returns (bytes memory out) {
        out = new bytes(data.length);
        for (uint i; i < data.length; i++) {
            bytes32 k = keccak256(abi.encodePacked(key, nonce, i / 32));
            out[i]    = data[i] ^ k[i % 32];
        }
    }
}

library HMAC {
    /// @dev HMAC‑SHA256 stub using keccak256
    function mac(bytes memory key, bytes memory msg) internal pure returns (bytes32) {
        bytes32 k = key.length > 32
            ? keccak256(key)
            : bytes32(bytes.concat(key, new bytes(32 - key.length)));
        bytes32 o_key = k ^ hex"5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c";
        bytes32 i_key = k ^ hex"3636363636363636363636363636363636363636363636363636363636363636";
        return keccak256(abi.encodePacked(o_key, keccak256(abi.encodePacked(i_key, msg))));
    }
}

////////////////////////////////////////////////////////////////////////////////
// 1) Keystream Reuse (Static Nonce)
//    ────────────────────────────────────────────────────────────────────────
//    Vulnerable: always uses nonce=0 → identical keystream for all messages
//    Attack: C1 ⊕ C2 = P1 ⊕ P2 leaks plaintext XOR
////////////////////////////////////////////////////////////////////////////////
contract StreamCipherVulnReuse {
    using StreamCipher for bytes;

    bytes32 public key;
    mapping(uint256 => bytes) public cipher;

    constructor(bytes32 _key) { key = _key; }

    function encrypt(uint256 id, bytes calldata pt) external {
        cipher[id] = StreamCipher.encrypt(key, 0, pt);
    }
}

contract Attack_StreamReuse {
    StreamCipherVulnReuse public target;
    constructor(StreamCipherVulnReuse _t) { target = _t; }

    function leakXor(uint256 i1, uint256 i2) external view returns (bytes memory) {
        bytes memory c1 = target.cipher(i1);
        bytes memory c2 = target.cipher(i2);
        require(c1.length == c2.length, "length");
        bytes memory out = new bytes(c1.length);
        for (uint i; i < c1.length; i++) {
            out[i] = c1[i] ^ c2[i];
        }
        return out; // equals P1 ⊕ P2
    }
}

contract StreamCipherSafeReuse {
    using StreamCipher for bytes;

    bytes32 public key;
    mapping(uint256 => bytes) public cipher;
    mapping(uint256 => bool)  public used;

    constructor(bytes32 _key) { key = _key; }

    /// @notice requires unique nonce (here using id as nonce)
    function encrypt(uint256 id, bytes calldata pt) external {
        if (used[id]) revert Stream__NonceReuse();
        cipher[id] = StreamCipher.encrypt(key, id, pt);
        used[id]   = true;
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) Hard‑Coded Key Vulnerability
//    ────────────────────────────────────────────────────────────────────────
//    Vulnerable: key baked as public constant → anyone can read it
////////////////////////////////////////////////////////////////////////////////
contract StreamCipherVulnHardcoded {
    using StreamCipher for bytes;

    bytes32 public constant KEY = 
        hex"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    mapping(uint256 => bytes) public cipher;

    function encrypt(uint256 id, bytes calldata pt) external {
        cipher[id] = StreamCipher.encrypt(KEY, id, pt);
    }
}

contract Attack_StreamHardcoded {
    StreamCipherVulnHardcoded public target;
    constructor(StreamCipherVulnHardcoded _t) { target = _t; }

    function stealKey() external pure returns (bytes32) {
        return StreamCipherVulnHardcoded.KEY;
    }
}

contract StreamCipherSafeHardcoded {
    using StreamCipher for bytes;

    bytes32 public DOMAIN;
    bytes32 private constant TYPEHASH = keccak256(
        "DeriveKey(uint256 nonce,uint256 expiry)"
    );
    mapping(uint256 => bool) public used;
    mapping(uint256 => bytes) public cipher;

    constructor() {
        DOMAIN = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
            keccak256("StreamCipherSafeHardcoded"),
            block.chainid,
            address(this)
        ));
    }

    /// @notice off‑chain manager signs (nonce,expiry) to authorize key derivation
    function encrypt(
        uint256 id,
        bytes calldata pt,
        uint256 nonce,
        uint256 expiry,
        bytes calldata sig
    ) external {
        require(block.timestamp <= expiry, "expired");
        require(!used[nonce], "replayed");

        // EIP‑712 digest
        bytes32 structHash = keccak256(abi.encode(TYPEHASH, nonce, expiry));
        bytes32 digest     = keccak256(abi.encodePacked("\x19\x01", DOMAIN, structHash));
        address signer     = ecrecover(digest, uint8(sig[64]), bytes32(sig[:32]), bytes32(sig[32:64]));
        if (signer == address(0) || signer != address(this)) revert Stream__Unauthorized();

        used[nonce]       = true;
        bytes32 sessionKey = keccak256(abi.encodePacked(signer, nonce, expiry, id));
        cipher[id]        = StreamCipher.encrypt(sessionKey, id, pt);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) Predictable Nonce (block.timestamp)
//    ────────────────────────────────────────────────────────────────────────
//    Vulnerable: uses block.timestamp as nonce → attacker can brute‑force
////////////////////////////////////////////////////////////////////////////////
contract StreamCipherVulnPredictable {
    using StreamCipher for bytes;

    bytes32 public key;
    mapping(uint256 => bytes) public cipher;

    constructor(bytes32 _key) { key = _key; }

    function encrypt(uint256 id, bytes calldata pt) external {
        uint256 nonce = block.timestamp; // predictable
        cipher[id]    = StreamCipher.encrypt(key, nonce, pt);
    }
}

contract Attack_StreamPredictable {
    StreamCipherVulnPredictable public target;
    constructor(StreamCipherVulnPredictable _t) { target = _t; }

    /// @notice brute‑force the timestamp in ±window range
    function guessNonce(uint256 id, bytes calldata pt, uint256 window)
        external view returns (uint256)
    {
        bytes memory c = target.cipher(id);
        for (int256 dt = -int256(window); dt <= int256(window); dt++) {
            uint256 ts = uint256(int256(block.timestamp) + dt);
            bytes memory test = StreamCipher.encrypt(target.key(), ts, pt);
            if (keccak256(test) == keccak256(c)) {
                return ts;
            }
        }
        revert("not found");
    }
}

contract StreamCipherSafePredictable {
    using StreamCipher for bytes;

    bytes32 public key;
    mapping(uint256 => bytes) public cipher;
    mapping(uint256 => bool)  public usedNonce;

    constructor(bytes32 _key) { key = _key; }

    /// @notice requires caller to supply a fresh, unpredictable nonce
    function encrypt(uint256 id, bytes calldata pt, uint256 nonce) external {
        if (usedNonce[nonce]) revert Stream__PredictableNonce();
        usedNonce[nonce] = true;
        cipher[id]       = StreamCipher.encrypt(key, nonce, pt);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) Missing Authentication (No MAC)
//    ────────────────────────────────────────────────────────────────────────
//    Vulnerable: attacker can flip bits in ciphertext → plaintext flipped
////////////////////////////////////////////////////////////////////////////////
contract StreamCipherVulnNoMac {
    using StreamCipher for bytes;

    bytes32 public key;
    mapping(uint256 => bytes) public cipher;

    constructor(bytes32 _key) { key = _key; }

    function encrypt(uint256 id, bytes calldata pt) external {
        cipher[id] = StreamCipher.encrypt(key, id, pt);
    }
    function decrypt(uint256 id) external view returns (bytes memory) {
        return StreamCipher.encrypt(key, id, cipher[id]);
    }
}

contract Attack_StreamNoMac {
    StreamCipherVulnNoMac public target;
    constructor(StreamCipherVulnNoMac _t) { target = _t; }

    /// flip one byte and observe plaintext bit‑flip
    function tamperAndDecrypt(uint256 id, uint idx, bytes1 delta) external view returns (bytes memory) {
        bytes memory c = target.cipher(id);
        c[idx] ^= delta;
        // decrypt with modified ciphertext
        return StreamCipher.encrypt(target.key(), id, c);
    }
}

contract StreamCipherSafeMac {
    using StreamCipher for bytes;
    using HMAC        for bytes;

    bytes32 public key;
    mapping(uint256 => bytes)  public cipher;
    mapping(uint256 => bytes32) public tag;

    constructor(bytes32 _key) { key = _key; }

    function encrypt(uint256 id, bytes calldata pt) external {
        bytes memory c     = StreamCipher.encrypt(key, id, pt);
        bytes32 t          = HMAC.mac(abi.encodePacked(key), c);
        cipher[id]         = c;
        tag[id]            = t;
    }

    function decrypt(uint256 id) external view returns (bytes memory) {
        bytes memory c = cipher[id];
        if (HMAC.mac(abi.encodePacked(key), c) != tag[id]) revert Stream__InvalidMac();
        return StreamCipher.encrypt(key, id, c);
    }
}
