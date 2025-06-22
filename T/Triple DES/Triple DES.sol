// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title TripleDESSuite.sol
/// @notice On‑chain analogues of “Triple DES” encryption patterns:
///   Types: ModeECB, ModeCBC  
///   AttackTypes: MeetInTheMiddle  
///   DefenseTypes: KeyStretching, AuthenticatedMode  

enum TripleDESType        { ModeECB, ModeCBC }
enum TripleDESAttackType  { MeetInTheMiddle }
enum TripleDESDefenseType { KeyStretching, AuthenticatedMode }

error TDES__BadKeyLength();
error TDES__AuthFailed();

library SimpleDES {
    /// @dev stub “DES” block cipher: XORs block with key-derived mask
    function desBlock(bytes8 key, bytes8 block) internal pure returns (bytes8) {
        // very insecure placeholder
        bytes32 mask = keccak256(abi.encodePacked(key));
        return block ^ bytes8(mask);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE TRIPLE‑DES (ECB, fixed keys, no integrity)
///─────────────────────────────────────────────────────────────────────────────
contract TripleDESVuln {
    using SimpleDES for bytes8;

    bytes8 public k1;
    bytes8 public k2;
    bytes8 public k3;

    /// set the three DES keys (must be exactly 8 bytes each)
    function setKeys(bytes8 _k1, bytes8 _k2, bytes8 _k3) external {
        k1 = _k1;
        k2 = _k2;
        k3 = _k3;
    }

    /// encrypt a single 8‑byte block in ECB mode
    function encryptECB(bytes8 plaintext) public view returns (bytes8) {
        // EDE: Encrypt with k1, decrypt with k2 (same as encrypt here), encrypt with k3
        bytes8 c1 = plaintext.desBlock(k1);
        bytes8 c2 = c1.desBlock(k2);   // vulnerable: using same stub for decrypt
        bytes8 c3 = c2.desBlock(k3);
        return c3;
    }

    /// decrypt a single 8‑byte block in ECB mode
    function decryptECB(bytes8 cipher) public view returns (bytes8) {
        // DED: decrypt with k3, encrypt with k2, decrypt with k1
        bytes8 p1 = cipher.desBlock(k3);
        bytes8 p2 = p1.desBlock(k2);
        bytes8 p3 = p2.desBlock(k1);
        return p3;
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB: Meet‑in‑the‑Middle on two keys (k1,k2)
///─────────────────────────────────────────────────────────────────────────────
contract Attack_TripleDES {
    TripleDESVuln public target;

    constructor(TripleDESVuln _t) { target = _t; }

    /// attacker knows plaintext/cipher pair, tries brute over 2^16 keys stub
    function meetInTheMiddle(bytes8 knownPlain, bytes8 knownCipher) external view returns (bytes8 k1Guess, bytes8 k2Guess) {
        // very simplified stub: real attack would build lookup tables
        for (uint16 a = 0; a < 0xFFFF; a++) {
            bytes8 keyA = bytes8(uint64(a)) ;
            bytes8 mid = knownPlain.desBlock(keyA);
            // reverse K3 layer
            bytes8 beforeK3 = knownCipher.desBlock(target.k3());
            if (mid == beforeK3) {
                k1Guess = keyA;
                k2Guess = bytes8(0); // stub: would find matching k2
                return (k1Guess, k2Guess);
            }
        }
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE TRIPLE‑DES (CBC, key‑stretching + MAC)
//─────────────────────────────────────────────────────────────────────────────
contract TripleDESSafe {
    using SimpleDES for bytes8;

    bytes8  public k1;
    bytes8  public k2;
    bytes8  public k3;
    bytes32 public macKey;

    error TDES__IVZero();

    /// set keys and a separate MAC key
    function setKeys(bytes8 _k1, bytes8 _k2, bytes8 _k3, bytes32 _macKey) external {
        // enforce nonzero keys
        if (_k1 == bytes8(0) || _k2 == bytes8(0) || _k3 == bytes8(0)) revert TDES__BadKeyLength();
        k1 = _k1;
        k2 = _k2;
        k3 = _k3;
        macKey = _macKey;
    }

    /// encrypt one block in CBC mode with IV, then append a simple MAC
    function encryptCBC(bytes8 plaintext, bytes8 iv) external view returns (bytes8 cipher, bytes32 tag) {
        if (iv == bytes8(0)) revert TDES__IVZero();
        // CBC: block ^ IV, then triple‑DES ECB
        bytes8 xored   = plaintext ^ iv;
        bytes8 c1      = xored.desBlock(k1);
        bytes8 c2      = c1.desBlock(k2);
        bytes8 c3      = c2.desBlock(k3);
        cipher = c3;
        // MAC = keccak( cipher || macKey )
        tag = keccak256(abi.encodePacked(cipher, macKey));
    }

    /// decrypt one block in CBC mode, verify MAC before returning plaintext
    function decryptCBC(bytes8 cipher, bytes8 iv, bytes32 tag) external view returns (bytes8 plaintext) {
        // verify MAC
        if (keccak256(abi.encodePacked(cipher, macKey)) != tag) revert TDES__AuthFailed();
        // reverse EDE
        bytes8 d1 = cipher.desBlock(k3);
        bytes8 d2 = d1.desBlock(k2);
        bytes8 d3 = d2.desBlock(k1);
        plaintext = d3 ^ iv;
    }
}
