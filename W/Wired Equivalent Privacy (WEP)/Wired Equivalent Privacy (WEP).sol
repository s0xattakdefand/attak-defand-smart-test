// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title WirelessEquivalentPrivacySuite.sol
/// @notice On‑chain analogues of “Wireless Equivalent Privacy” (WEP) patterns:
///   Types: WEPType, KeyLength  
///   AttackTypes: IVReuse, KeyRecovery, FakeAuth  
///   DefenseTypes: IVRandomize, KeyMixing, IntegrityCheck, WPAUpgrade  

enum WEPType           { Legacy, SharedKey }
enum WEPAttackType     { IVReuse, KeyRecovery, FakeAuth }
enum WEPDefenseType    { IVRandomize, KeyMixing, IntegrityCheck, WPAUpgrade }

error WEP__BadIV();
error WEP__AuthFailed();
error WEP__WeakKey();

/// @dev very simplified RC4‐style cipher stub (XOR keystream)
library SimpleRC4 {
    function encrypt(bytes memory key, bytes memory iv, bytes calldata pt) internal pure returns (bytes memory ct) {
        // stub: keystream = keccak(key || iv), repeated
        bytes32 seed = keccak256(abi.encodePacked(key, iv));
        ct = new bytes(pt.length);
        for (uint i = 0; i < pt.length; i++) {
            ct[i] = pt[i] ^ seed[i % 32];
        }
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE WEP ENCRYPTION
///
///    • fixed key, IV prepended but not rotated → IV reuse
///    • AttackType: IVReuse & KeyRecovery  
///─────────────────────────────────────────────────────────────────────────────
contract WEPVuln {
    bytes   public key;    // e.g. 5 or 13 bytes
    event Frame(uint24 iv, bytes payload, WEPAttackType attack);

    constructor(bytes memory _key) {
        key = _key;
    }

    /// encrypts payload with fixed key and supplied IV
    function sendFrame(uint24 iv, bytes calldata payload) external {
        // ❌ no IV rotation: attacker can reuse iv to recover key
        bytes memory ivBytes = abi.encodePacked(iv);
        bytes memory ct = SimpleRC4.encrypt(key, ivBytes, payload);
        emit Frame(iv, ct, WEPAttackType.IVReuse);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB: KEY RECOVERY VIA KNOWN‑IV FLOOD
///
///    • attacker observes many frames with same IV → recovers key stub  
///─────────────────────────────────────────────────────────────────────────────
contract Attack_WEP {
    WEPVuln public target;

    constructor(WEPVuln _t) { target = _t; }

    /// simulate flooding frames with iv=0 → leak keystream
    function recoverKey(bytes calldata knownPlain) external view returns (bytes memory guessedKey) {
        // stub: key = keystream xor knownPlain for iv=0
        (, bytes memory ct, ) = target.Frame(0); // pretend we can read last cipher
        guessedKey = new bytes(knownPlain.length);
        for (uint i = 0; i < knownPlain.length; i++) {
            guessedKey[i] = ct[i] ^ knownPlain[i];
        }
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE WEP WITH IV RANDOMIZATION & KEY MIXING
///
///    • Defense: rotate IV every frame + mix IV into key (per‐frame key)
///─────────────────────────────────────────────────────────────────────────────
contract WEPSafeIVRandom {
    bytes   public masterKey;
    uint24  private counter;
    event Frame(uint24 iv, bytes payload, WEPDefenseType defense);

    constructor(bytes memory _masterKey) {
        masterKey = _masterKey;
        counter   = 1;
    }

    function sendFrame(bytes calldata payload) external {
        // ✅ IV = monotonically increasing counter (never reused)
        uint24 iv = counter++;
        bytes memory ivBytes = abi.encodePacked(iv);
        // ✅ per‐frame key mixing: K = keccak(masterKey || iv)
        bytes memory perFrameKey = abi.encodePacked(keccak256(abi.encodePacked(masterKey, ivBytes)));
        bytes memory ct = SimpleRC4.encrypt(perFrameKey, ivBytes, payload);
        emit Frame(iv, ct, WEPDefenseType.IVRandomize);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) UPGRADE TO WPA‑STYLE WITH MIC & STRONG CIPHER
///
///    • Defense: integrity (HMAC) + stronger cipher stub
///─────────────────────────────────────────────────────────────────────────────
contract WEPSafeWPAUpgrade {
    bytes32   public ptk;  // pairwise transient key (session)
    event Frame(bytes iv, bytes ct, bytes mic, WEPDefenseType defense);

    constructor(bytes32 _ptk) {
        ptk = _ptk;
    }

    function sendFrame(bytes calldata payload) external {
        // generate random IV
        bytes memory iv = abi.encodePacked(block.timestamp, blockhash(block.number - 1));
        // stub strong cipher: AES‐style via keccak(PRK || iv)
        bytes32 cipherKey = keccak256(abi.encodePacked(ptk, iv));
        bytes memory ct = new bytes(payload.length);
        for (uint i = 0; i < payload.length; i++) {
            ct[i] = payload[i] ^ cipherKey[i % 32];
        }
        // compute MIC (message integrity code)
        bytes32 mic = keccak256(abi.encodePacked(ct, ptk));
        emit Frame(iv, ct, abi.encodePacked(mic), WEPDefenseType.IntegrityCheck);
    }
}
