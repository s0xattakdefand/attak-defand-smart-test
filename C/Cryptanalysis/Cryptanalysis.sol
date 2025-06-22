// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title CryptanalysisSuite.sol
/// @notice On‑chain analogues of common “Cryptanalysis” patterns:
///   Types: BruteForce, Differential, Linear, SideChannel  
///   AttackTypes: KeyBrute, DiffAttack, LinearAttack, TimingLeak  
///   DefenseTypes: KeyLengthIncrease, SBoxRotation, ConstantTime, Masking  

enum CryptanalysisType        { BruteForce, Differential, Linear, SideChannel }
enum CryptanalysisAttackType  { KeyBrute, DiffAttack, LinearAttack, TimingLeak }
enum CryptanalysisDefenseType { KeyLengthIncrease, SBoxRotation, ConstantTime, Masking }

error CA__KeyTooShort();
error CA__BadPadding();
error CA__TimingLeak();
error CA__AlreadyMasked();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE CIPHER (small key, static S‑box, branch‑based padding)
///
///    • no defense: key is 8 bits, S‑box fixed, padding branches leak timing  
///    • Attack: KeyBrute + TimingLeak  
///─────────────────────────────────────────────────────────────────────────────
contract CryptanalysisVuln {
    uint8 public key;                   // 8-bit key → brute‑force trivial
    uint8[16] public sbox;              // static small S‑box
    event Ciphertext(bytes cipher, CryptanalysisAttackType attack);

    constructor(uint8 initKey) {
        key = initKey;
        // simple stub S‑box
        for (uint8 i = 0; i < 16; i++) {
            sbox[i] = i ^ 0xA;
        }
    }

    /// encrypt data with a single-byte XOR + S‑box + PKCS7‑style padding
    function encrypt(bytes calldata data) external returns (bytes memory) {
        // branch-based padding leaks length
        uint8 pad = uint8(16 - (data.length % 16));
        bytes memory padded = abi.encodePacked(data);
        for (uint i = data.length; i < data.length + pad; i++) {
            padded.push(bytes1(pad));
        }
        // simple block transform: byte → sbox[(b ^ key) & 0xF]
        bytes memory out = new bytes(padded.length);
        for (uint i = 0; i < padded.length; i++) {
            uint8 b = uint8(padded[i]);
            out[i] = bytes1(sbox[(b ^ key) & 0xF]);
        }
        emit Ciphertext(out, CryptanalysisAttackType.TimingLeak);
        return out;
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB: brute‑force key + timing side‑channel
///
///    • tries all 256 keys offline by measuring encrypt gas/response time  
///─────────────────────────────────────────────────────────────────────────────
contract Attack_Cryptanalysis {
    CryptanalysisVuln public target;
    constructor(CryptanalysisVuln _t) {
        target = _t;
    }

    /// stub brute: calls encrypt with guesses, observes gas used
    function bruteForce(bytes calldata sample) external view returns (uint8 foundKey) {
        uint256 bestGas = type(uint256).max;
        for (uint16 k = 0; k < 256; k++) {
            try target.encrypt{gas:100000}(sample) returns (bytes memory) {
                uint256 gasLeft = gasleft();
                if (gasLeft < bestGas) {
                    bestGas = gasLeft;
                    foundKey = uint8(k);
                }
            } catch {}
        }
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE CIPHER WITH INCREASED KEY & ROTATING S‑BOX
///
///    • Defense: KeyLengthIncrease (256‑bit key) + SBoxRotation per block  
///─────────────────────────────────────────────────────────────────────────────
contract CryptanalysisSafe {
    bytes32 public key;                // 256-bit key
    uint8[256] public sbox;            // full 8-bit S‑box
    event Ciphertext(bytes cipher, CryptanalysisDefenseType defense);

    constructor(bytes32 initKey) {
        key = initKey;
        // initialize identity S‑box
        for (uint16 i = 0; i < 256; i++) {
            sbox[i] = uint8(i);
        }
    }

    /// encrypt with per-block S‑box rotation
    function encrypt(bytes calldata data) external returns (bytes memory) {
        bytes memory out = new bytes(data.length);
        uint8 round = 0;
        for (uint i = 0; i < data.length; i++) {
            // rotate S‑box index by round counter
            uint8 b = uint8(data[i]);
            out[i] = bytes1(sbox[(uint16(b) + round) & 0xFF] ^ uint8(uint256(key[i % 32])));
            round++;
        }
        emit Ciphertext(out, CryptanalysisDefenseType.SBoxRotation);
        return out;
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SIDE‑CHANNEL RESISTANT CIPHER (constant‑time + masking)
///
///    • Defense: ConstantTime (no branches) + Masking (per‑byte random)  
///─────────────────────────────────────────────────────────────────────────────
contract CryptanalysisSafeSideChannel {
    bytes32 public key;
    mapping(bytes32 => bool) private _usedMask;
    event Ciphertext(bytes cipher, CryptanalysisDefenseType defense);

    constructor(bytes32 initKey) {
        key = initKey;
    }

    /// constant‑time masked XOR
    function encrypt(bytes calldata data, bytes32 mask) external returns (bytes memory) {
        require(!_usedMask[mask], "Mask reused");
        _usedMask[mask] = true;

        bytes memory out = new bytes(data.length);
        uint256 kacc = uint256(key) ^ uint256(mask);
        for (uint i = 0; i < data.length; i++) {
            // no data‑dependent branches
            out[i] = bytes1(bytes1(uint8(data[i]) ^ uint8(kacc >> ((i % 32) * 8))));
        }
        emit Ciphertext(out, CryptanalysisDefenseType.Masking);
        return out;
    }
}
