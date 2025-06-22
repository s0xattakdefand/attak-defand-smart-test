// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title WiretappingSuite.sol
/// @notice On‑chain analogues of “Wiretapping” patterns:
///   Types: Passive, Active, Correlation, Replay  
///   AttackTypes: Eavesdrop, PacketInjection, CorrelationAttack, ReplayAttack  
///   DefenseTypes: Encryption, HMACAuth, NoisePadding, TimestampCheck  

enum WiretapType           { Passive, Active, Correlation, Replay }
enum WiretapAttackType     { Eavesdrop, PacketInjection, CorrelationAttack, ReplayAttack }
enum WiretapDefenseType    { Encryption, HMACAuth, NoisePadding, TimestampCheck }

error WT__NotEncrypted();
error WT__BadAuth();
error WT__BadPadding();
error WT__StaleLog();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE LOGGER (Passive Wiretapping)
///
///    • logs all data in clear  
///    • Attack: Eavesdrop  
///─────────────────────────────────────────────────────────────────────────────
contract WiretapVuln {
    event DataLogged(
        address indexed source,
        bytes          data,
        WiretapAttackType attack
    );

    /// ❌ logs raw data
    function logData(bytes calldata data) external {
        emit DataLogged(msg.sender, data, WiretapAttackType.Eavesdrop);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB (Active Injection)
///
///    • uses the vulnerable log to inject forged packets  
///─────────────────────────────────────────────────────────────────────────────
contract Attack_Wiretap {
    WiretapVuln public target;
    constructor(WiretapVuln _t) { target = _t; }

    /// inject a forged packet
    function inject(bytes calldata fakeData) external {
        target.logData(fakeData);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE LOGGER WITH ENCRYPTION
///
///    • Defense: Encryption – only encrypted payloads allowed  
///─────────────────────────────────────────────────────────────────────────────
contract WiretapSafeEncryption {
    event DataLoggedEnc(
        address indexed source,
        bytes          cipher,
        WiretapDefenseType defense
    );

    /// ✅ require first byte 0x01 to indicate “encrypted”
    function logEncrypted(bytes calldata cipher) external {
        if (cipher.length == 0 || cipher[0] != 0x01) revert WT__NotEncrypted();
        emit DataLoggedEnc(msg.sender, cipher, WiretapDefenseType.Encryption);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE LOGGER WITH HMAC AUTH & NOISE PADDING
///
///    • Defense: HMACAuth – verify mac  
///               NoisePadding – length must be multiple of 32  
///─────────────────────────────────────────────────────────────────────────────
contract WiretapSafeAuthPadding {
    bytes32 public immutable key;
    mapping(bytes32 => uint256) public lastLogged; // timestamp of last log by HMAC

    event DataLoggedAuth(
        address indexed source,
        bytes          data,
        WiretapDefenseType defense,
        uint256        timestamp
    );

    constructor(bytes32 macKey) {
        key = macKey;
    }

    /// ✅ require data length % 32 == 0 (padding) and valid HMAC
    function logSecure(bytes calldata data, bytes32 mac, uint256 ts) external {
        // padding check
        if (data.length % 32 != 0) revert WT__BadPadding();
        // freshness check (allow ±5 minutes)
        if (ts + 5 minutes < block.timestamp || ts > block.timestamp + 5 minutes) {
            revert WT__StaleLog();
        }
        // HMAC: keccak256(data || key || ts)
        bytes32 expected = keccak256(abi.encodePacked(data, key, ts));
        if (expected != mac) revert WT__BadAuth();
        // record and emit
        lastLogged[mac] = block.timestamp;
        emit DataLoggedAuth(msg.sender, data, WiretapDefenseType.HMACAuth, ts);
    }
}
