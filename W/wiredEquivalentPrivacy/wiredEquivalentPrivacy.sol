// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title WEPProtocolSuite.sol
/// @notice On‐chain analogues of “Wired Equivalent Privacy” (WEP) patterns:
///   Types: OpenSystem, SharedKey, PSK40, PSK104  
///   AttackTypes: IVWeakness, KeyRecovery, PacketInjection, Replay  
///   DefenseTypes: KeyRotation, IVRandomization, EncryptedCCK, WPAUpgrade

enum WEPType             { OpenSystem, SharedKey, PSK40, PSK104 }
enum WEPAttackType       { IVWeakness, KeyRecovery, PacketInjection, Replay }
enum WEPDefenseType      { KeyRotation, IVRandomization, EncryptedCCK, WPAUpgrade }

error WEP__NotOwner();
error WEP__TooFrequent();
error WEP__WPANotEnabled();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE WEP IMPLEMENTATION
//
//    • ❌
