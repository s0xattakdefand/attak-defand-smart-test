// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title SymCryptSuite.sol
/// @notice Four on‑chain analogues of common “Symmetric Cryptography” patterns:
///   1) XOR Cipher Reuse  
///   2) Static‑IV “AES” Stub  
///   3) Padding‑Oracle Style Leak  
///   4) Encrypt‑Then‑Authenticate Missing MAC  

////////////////////////////////////////////////////////////////////////
// Shared XOR‑Cipher Library (for all examples)
////////////////////////////////////////////////////////////////////////
library XORCipher {
    function encrypt(bytes memory key, bytes memory data) internal pure returns (bytes memory) {
        bytes memory out = new bytes(data.length);
        for (uint i = 0; i < data.length; i++) {
            out[i] = data[i] ^ key[i % key.length];
        }
        return out;
    }
}

////////////////////////////////////////////////////////////////////////
// 1) XOR CIPHER REUSE
//    • Vulnerable: same key used for multiple messages → keystream reuse
//    • Attack: E1 ^ E2 = P1 ^ P2 leaks plaintext XOR
//    • Defense: derive per‑message subkey with nonce
////////////////////////////////////////////////////////////////////////
contract SymCrypt_XORVuln {
    using XORCipher for bytes;
    bytes public key;
    mapping(uint256 => bytes) public ciphertext;

    constructor(bytes memory _key) { key = _key; }

    function encryptAndStore(uint256 id, bytes calldata plaintext) external {
        ciphertext[id] = plaintext.encrypt(key);
    }
}

contract Attack_XORReuse {
    SymCrypt_XORVuln public target;
    constructor(SymCrypt_XORVuln _t) { target = _t; }

    function leakXor(uint256 id1, uint256 id2) external view returns (bytes memory) {
        bytes memory c1 = target.ciphertext(id1);
        bytes memory c2 = target.ciphertext(id2);
        require(c1.length == c2.length, "len");
        bytes memory out = new bytes(c1.length);
        for (uint i; i < c1.length; i++) {
            out[i] = c1[i] ^ c2[i];
        }
        return out; // equals P1 ^ P2
    }
}

contract SymCrypt_XORSafe {
    using XORCipher for bytes;
    bytes public masterKey;
    mapping(uint256 => bytes) public ciphertext;
    mapping(uint256 => bool) public usedNonce;

    constructor(bytes memory _masterKey) { masterKey = _masterKey; }

    function encryptAndStore(
        uint256 id,
        bytes calldata plaintext,
        uint256 nonce
    ) external {
        require(!usedNonce[nonce], "nonce used");
        usedNonce[nonce] = true;
        // derive per‑message key
        bytes32 sub = keccak256(abi.encodePacked(masterKey, nonce));
        bytes memory subKey = abi.encodePacked(sub);
        ciphertext[id] = plaintext.encrypt(subKey);
    }
}

////////////////////////////////////////////////////////////////////////
// 2) STATIC‑IV “AES” STUB
//    • Vulnerable: fixed IV → identical plaintext blocks give identical ciphertext
//    • Attack: detect repeated blocks and mount replay
//    • Defense: require random IV per message
////////////////////////////////////////////////////////////////////////
library AESStub {
    function encryptWithIV(bytes32 iv, bytes memory data) internal pure returns (bytes memory) {
        // stub: XOR block‑wise with iv repeated
        bytes memory out = new bytes(data.length);
        for (uint i; i < data.length; i++) {
            out[i] = data[i] ^ iv[i % 32];
        }
        return out;
    }
}

contract SymCrypt_AESVuln {
    using AESStub for bytes;
    bytes32 public key;      // unused in stub
    bytes32 public iv = hex"0000000000000000000000000000000000000000000000000000000000000000";
    mapping(uint256 => bytes) public ctext;

    constructor(bytes32 _k) { key = _k; }

    function encryptStore(uint256 id, bytes calldata pt) external {
        ctext[id] = pt.encryptWithIV(iv);
    }
}

contract Attack_StaticIV {
    SymCrypt_AESVuln public target;
    constructor(SymCrypt_AESVuln _t) { target = _t; }

    function detectRepeat(uint256 id1, uint256 id2) external view returns (bool) {
        bytes memory c1 = target.ctext(id1);
        bytes memory c2 = target.ctext(id2);
        // if any block matches exactly, plaintext block repeated
        for (uint i; i + 32 <= c1.length; i += 32) {
            for (uint j; j + 32 <= c2.length; j += 32) {
                bool eq = true;
                for (uint k; k < 32; k++) {
                    if (c1[i+k] != c2[j+k]) { eq = false; break; }
                }
                if (eq) return true;
            }
        }
        return false;
    }
}

contract SymCrypt_AESSafe {
    using AESStub for bytes;
    bytes32 public key;
    mapping(uint256 => bytes) public ctext;

    constructor(bytes32 _k) { key = _k; }

    function encryptStore(
        uint256 id,
        bytes calldata pt,
        bytes32 iv
    ) external {
        // iv must be unpredictable
        require(iv != 0, "bad iv");
        ctext[id] = pt.encryptWithIV(iv);
    }
}

////////////////////////////////////////////////////////////////////////
// 3) PADDING‑ORACLE STYLE LEAK
//    • Vulnerable: decryption reverts differently on bad padding → oracle
//    • Attack: probe ciphertexts and learn plaintext via error codes
//    • Defense: constant‑time error or generic revert
////////////////////////////////////////////////////////////////////////
contract SymCrypt_PadVuln {
    using XORCipher for bytes;
    bytes public key;
    mapping(uint256 => bytes) public ctext;

    constructor(bytes memory _k) { key = _k; }

    function encryptStore(uint256 id, bytes calldata pt) external {
        // pad to 32 bytes with zeros
        bytes memory data = new bytes(((pt.length+31)/32)*32);
        for (uint i; i < pt.length; i++) data[i] = pt[i];
        // stub decrypt/encrypt by XOR
        ctext[id] = data.encrypt(key);
    }

    function decrypt(uint256 id) external view returns (bytes memory) {
        bytes memory data = ctext[id].encrypt(key);
        // naive unpadding: find last nonzero
        uint len = data.length;
        while (len > 0 && data[len-1] == 0) {
            if (data[len-1] != 0) revert("pad error"); // wrong pad? impossible here
            len--;
        }
        // return first len bytes
        bytes memory pt = new bytes(len);
        for (uint i; i < len; i++) pt[i] = data[i];
        return pt;
    }
}

contract Attack_PadOracle {
    SymCrypt_PadVuln public target;
    constructor(SymCrypt_PadVuln _t) { target = _t; }

    // "oracle" by catching revert vs return
    function probe(uint256 id) external returns (bool) {
        try target.decrypt(id) {
            return true; // good padding path
        } catch {
            return false; // pad error
        }
    }
}

contract SymCrypt_PadSafe {
    using XORCipher for bytes;
    bytes public key;
    mapping(uint256 => bytes) public ctext;

    constructor(bytes memory _k) { key = _k; }

    function encryptStore(uint256 id, bytes calldata pt) external {
        bytes memory data = new bytes(((pt.length+31)/32)*32);
        for (uint i; i < pt.length; i++) data[i] = pt[i];
        ctext[id] = data.encrypt(key);
    }

    function decrypt(uint256 id) external pure returns (bytes memory) {
        // do not reveal padding errors!
        // always return fixed‐length or generic revert
        revert("decryption unavailable");
    }
}

////////////////////////////////////////////////////////////////////////
// 4) MISSING MAC (Encrypt‑Then‑Authenticate)
//
//    • Vulnerable: ciphertext accepted without integrity check
//    • Attack: attacker flips bits in transit → garbled plaintext
//    • Defense: append HMAC and verify before decrypt
////////////////////////////////////////////////////////////////////////
library HMAC {
    function mac(bytes memory key, bytes memory msg) internal pure returns (bytes32) {
        bytes32 k = key.length > 32
            ? keccak256(key)
            : bytes32(bytes.concat(key, new bytes(32 - key.length)));
        bytes32 o_key = k ^ hex"5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c";
        bytes32 i_key = k ^ hex"3636363636363636363636363636363636363636363636363636363636363636";
        return keccak256(abi.encodePacked(o_key, keccak256(abi.encodePacked(i_key, msg))));
    }
}

contract SymCrypt_NoMACVuln {
    using XORCipher for bytes;
    bytes public key;
    mapping(uint256 => bytes) public ctext;
    constructor(bytes memory _k) { key = _k; }
    function encryptStore(uint256 id, bytes calldata pt) external {
        ctext[id] = pt.encrypt(key);
    }
    function decrypt(uint256 id) external view returns (bytes memory) {
        return ctext[id].encrypt(key);
    }
}

contract SymCrypt_MACSafe {
    using XORCipher for bytes;
    using HMAC for bytes;

    bytes public key;
    mapping(uint256 => bytes) public ctext;
    mapping(uint256 => bytes32) public tag;

    constructor(bytes memory _k) { key = _k; }

    function encryptStore(uint256 id, bytes calldata pt) external {
        bytes memory c = pt.encrypt(key);
        bytes32 t = HMAC.mac(key, c);
        ctext[id] = c;
        tag[id]   = t;
    }

    function decrypt(uint256 id) external view returns (bytes memory) {
        bytes memory c = ctext[id];
        require(HMAC.mac(key, c) == tag[id], "bad mac");
        return c.encrypt(key);
    }
}
