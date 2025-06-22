// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title TunnelSuite.sol
/// @notice On‑chain analogues of common “Tunnel” patterns:
///   • Types: GRE, IPSec, SSH, VXLAN  
///   • AttackTypes: SniffTraffic, MITM, PacketInjection, Replay  
///   • DefenseTypes: Encapsulation, Encryption, IntegrityCheck, ReplayProtection  

enum TunnelType           { GRE, IPSec, SSH, VXLAN }
enum TunnelAttackType     { SniffTraffic, MITM, PacketInjection, Replay }
enum TunnelDefenseType    { Encapsulation, Encryption, IntegrityCheck, ReplayProtection }

error TNL__Unauthorized();
error TNL__IntegrityFailed();
error TNL__Replayed();

////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE PLAINTEXT TUNNEL
//
//    • anyone may send “tunneled” data in clear
//    • Attack: SniffTraffic
////////////////////////////////////////////////////////////////////////
contract TunnelVuln {
    event TunnelSent(
        address indexed who,
        TunnelType         kind,
        bytes              data,
        TunnelAttackType   attack
    );

    /// ❌ no confidentiality or integrity
    function send(TunnelType kind, bytes calldata data) external {
        emit TunnelSent(msg.sender, kind, data, TunnelAttackType.SniffTraffic);
    }
}

////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//
//    • demonstrates MITM by replaying victim’s tunnel
////////////////////////////////////////////////////////////////////////
contract Attack_Tunnel {
    TunnelVuln public tunnel;
    event AttackExecuted(TunnelAttackType attack, bytes data);

    constructor(TunnelVuln _t) { tunnel = _t; }

    /// attacker replays captured data
    function replay(bytes calldata data) external {
        tunnel.send(TunnelType.GRE, data);
        emit AttackExecuted(TunnelAttackType.Replay, data);
    }
}

////////////////////////////////////////////////////////////////////////
// 3) SAFE ENCRYPTED TUNNEL
//
//    • Defense: Encryption + IntegrityCheck + ReplayProtection
////////////////////////////////////////////////////////////////////////
library TunnelCipher {
    function encrypt(bytes32 key, uint256 nonce, bytes calldata pt) internal pure returns (bytes memory ct) {
        ct = new bytes(pt.length);
        for (uint i; i < pt.length; i++) {
            bytes32 k = keccak256(abi.encodePacked(key, nonce, i / 32));
            ct[i]    = pt[i] ^ k[i % 32];
        }
    }
}

contract TunnelSafe {
    using TunnelCipher for bytes;

    bytes32 public immutable key;
    mapping(uint256 => bool) public usedNonces;

    event TunnelSentSafe(
        address indexed who,
        TunnelType          kind,
        bytes               ciphertext,
        TunnelDefenseType   defense
    );

    constructor(bytes32 _key) {
        key = _key;
    }

    /// ✅ encrypt + integrity via Keccak‑based stream, protect against replay
    function send(
        TunnelType kind,
        uint256    nonce,
        bytes calldata data
    ) external {
        if (usedNonces[nonce]) revert TNL__Replayed();
        usedNonces[nonce] = true;

        // encrypt
        bytes memory ct = data.encrypt(key, nonce);

        // integrity check stub: embed hash in event (off‑chain verify)
        bytes32 h = keccak256(ct);
        if (h == bytes32(0)) revert TNL__IntegrityFailed();

        emit TunnelSentSafe(msg.sender, kind, abi.encodePacked(h, ct), TunnelDefenseType.Encryption);
    }
}
