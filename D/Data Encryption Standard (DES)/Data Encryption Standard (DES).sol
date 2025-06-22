// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DataEncryptionStandardSuite.sol
/// @notice On‑chain analogues of “Data Encryption Standard” (DES) patterns:
///   Types: SingleDES, TripleDES  
///   AttackTypes: BruteForce, MeetInTheMiddle, WeakKeyExploit  
///   DefenseTypes: KeyLengthIncrease, KeyParityCheck, StrongSBox  

enum DataEncryptionStandardType       { SingleDES, TripleDES }
enum DataEncryptionStandardAttackType { BruteForce, MeetInTheMiddle, WeakKeyExploit }
enum DataEncryptionStandardDefenseType{ KeyLengthIncrease, KeyParityCheck, StrongSBox }

error DES__BadKey();
error DES__WeakKey();
error DES__BadParity();

library SimpleDES {
    /// @dev very insecure stub: XOR block with keccak-derived mask
    function desBlock(bytes8 key, bytes8 block) internal pure returns (bytes8) {
        bytes32 mask = keccak256(abi.encodePacked(key));
        return block ^ bytes8(mask);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE SINGLE‑DES (56‑bit key stub, no parity or checks)
///    • Attack: BruteForce by trying all 2^16 stub‑keys  
///─────────────────────────────────────────────────────────────────────────────
contract DESVuln {
    using SimpleDES for bytes8;

    bytes8 public key;

    /// set the DES key (no parity check)
    function setKey(bytes8 k) external {
        key = k;
    }

    /// encrypt one 8‑byte block
    function encrypt(bytes8 plaintext) external view returns (bytes8) {
        return plaintext.desBlock(key);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB: brute‑force DES
///    • AttackType: BruteForce  
///─────────────────────────────────────────────────────────────────────────────
contract Attack_DES {
    DESVuln public target;
    constructor(DESVuln _t) { target = _t; }

    /// tries all 2^16 stub‑keys (very simplified) to match known plaintext/cipher
    function bruteForce(bytes8 plain, bytes8 cipher) external view returns (bytes8 foundKey) {
        for (uint32 i = 0; i < type(uint16).max; i++) {
            bytes8 k = bytes8(uint64(i));
            if (SimpleDES.desBlock(k, plain) == cipher) {
                return k;
            }
        }
        return 0;
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE TRIPLE‑DES (KeyLengthIncrease)
///    • Defense: use three independent keys to resist brute‑force & MITM  
///─────────────────────────────────────────────────────────────────────────────
contract DESTripleDESafe {
    using SimpleDES for bytes8;

    bytes8 public k1;
    bytes8 public k2;
    bytes8 public k3;

    /// set three DES keys (must be nonzero)
    function setKeys(bytes8 _k1, bytes8 _k2, bytes8 _k3) external {
        if (_k1 == bytes8(0) || _k2 == bytes8(0) || _k3 == bytes8(0)) revert DES__BadKey();
        k1 = _k1;
        k2 = _k2;
        k3 = _k3;
    }

    /// triple‑DES EDE encryption stub
    function encrypt(bytes8 plaintext) external view returns (bytes8) {
        bytes8 c1 = plaintext.desBlock(k1);
        bytes8 c2 = c1.desBlock(k2);   // stub decrypt = same operation
        return c2.desBlock(k3);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE SINGLE‑DES WITH PARITY & S‑BOX (KeyParityCheck, StrongSBox)
///    • Defense: require odd parity on key bytes + use rotating S‑box stub  
///─────────────────────────────────────────────────────────────────────────────
contract DESSafeParityCheck {
    bytes8 public key;
    bytes8[16] private sbox;

    error DES__ParityInvalid();

    constructor() {
        // initialize a simple rotating S‑box
        for (uint8 i = 0; i < 16; i++) {
            sbox[i] = bytes8(uint64((i * 0x0F0F0F0F0F0F0F0F) ^ 0xA5A5A5A5A5A5A5A5));
        }
    }

    /// set key only if each byte has odd parity
    function setKey(bytes8 k) external {
        for (uint8 i = 0; i < 8; i++) {
            uint8 b = uint8(k[i]);
            // count bits
            uint8 count;
            for (uint8 j = 0; j < 8; j++) {
                count += (b >> j) & 1;
            }
            if (count % 2 == 0) revert DES__ParityInvalid();
        }
        key = k;
    }

    /// encrypt with one round of S‑box substitution + key XOR
    function encrypt(bytes8 plaintext) external view returns (bytes8) {
        bytes8 x = plaintext ^ key;
        // apply S‑box based on high nibble of each byte
        bytes8 out;
        for (uint8 i = 0; i < 8; i++) {
            uint8 nibble = uint8(x[i]) >> 4;
            out |= bytes8(sbox[nibble])[i] & bytes8(0xFF << (i*8));
        }
        return out;
    }
}
