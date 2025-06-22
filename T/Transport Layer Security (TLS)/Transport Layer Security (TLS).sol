// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title TransportLayerSecuritySuite.sol
/// @notice Four “Transport Layer Security” patterns with common pitfalls and hardened defenses.

enum TLSLayerType        { Handshake, RecordLayer, Heartbeat, Renegotiation }
enum TLSAttackType       { MITM, Eavesdrop, HeartbeatExploit, RenegSpoof }
enum TLSDefenseType      { CertValidation, EncryptRequire, BoundsCheck, SecureRenegotiation }

error TLS__CertInvalid();
error TLS__NotEncrypted();
error TLS__OutOfBounds();
error TLS__NotAllowed();

////////////////////////////////////////////////////////////////////////////////
// 1) HANDSHAKE WITHOUT CERT VALIDATION
//    • Vulnerable: any client may establish a session without verifying cert
//    • Attack: MITM registers session with bogus cert
//    • Defense: require trusted root signature on cert
////////////////////////////////////////////////////////////////////////////////
contract TLSVulnHandshake {
    struct Session { bool established; }
    mapping(address => Session) public sessions;

    /// ❌ no cert validation
    function handshake(address peer, bytes calldata cert) external {
        sessions[msg.sender].established = true;
    }
}

contract Attack_TLSHandshake {
    TLSVulnHandshake public target;
    constructor(TLSVulnHandshake _t) { target = _t; }

    /// attacker “MITM” establishes session with bogus cert
    function mitm() external {
        target.handshake(address(0xdead), "");
    }
}

contract TLSSafeHandshake {
    struct Session { bool established; }
    mapping(address => Session) public sessions;
    mapping(bytes32 => bool) public trustedRoots;
    event TLSDefended(address indexed who, TLSLayerType layer, TLSDefenseType defense);

    /// owner seeds trusted root hashes
    function addTrustedRoot(bytes32 root) external {
        trustedRoots[root] = true;
    }

    /// ✅ validate that certRoot is trusted
    function handshake(address peer, bytes calldata cert, bytes32 certRoot) external {
        if (!trustedRoots[certRoot]) revert TLS__CertInvalid();
        sessions[msg.sender].established = true;
        emit TLSDefended(msg.sender, TLSLayerType.Handshake, TLSDefenseType.CertValidation);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) RECORD LAYER WITHOUT ENCRYPTION
//    • Vulnerable: accepts plaintext records
//    • Attack: Eavesdrop reads clear data
//    • Defense: require record to be wrapped with an “encrypted” flag
////////////////////////////////////////////////////////////////////////////////
contract TLSVulnRecord {
    mapping(address => bytes) public records;

    function sendRecord(bytes calldata data) external {
        // ❌ stores plaintext
        records[msg.sender] = data;
    }
}

contract Attack_TLSRecord {
    TLSVulnRecord public target;
    constructor(TLSVulnRecord _t) { target = _t; }

    function eavesdrop(address victim) external view returns (bytes memory) {
        return target.records(victim);
    }
}

contract TLSSafeRecord {
    mapping(address => bytes) public records;
    event TLSDefended(address indexed who, TLSLayerType layer, TLSDefenseType defense);

    /// ✅ require that data is marked “encrypted” (first byte = 0x01)
    function sendRecord(bytes calldata data) external {
        if (data.length == 0 || data[0] != 0x01) revert TLS__NotEncrypted();
        records[msg.sender] = data;
        emit TLSDefended(msg.sender, TLSLayerType.RecordLayer, TLSDefenseType.EncryptRequire);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) HEARTBEAT WITHOUT BOUNDS CHECK
//    • Vulnerable: copies requested length without checking payload size (tiny fragment style)
//    • Attack: HeartbeatExploit reads beyond buffer
//    • Defense: enforce maximum payload length
////////////////////////////////////////////////////////////////////////////////
contract TLSVulnHeartbeat {
    bytes public lastPing;

    function heartbeat(bytes calldata payload, uint16 len) external {
        // ❌ no bounds check: may read <= len from payload
        lastPing = payload[:len];
    }
}

contract Attack_TLSHeartbeat {
    TLSVulnHeartbeat public target;
    constructor(TLSVulnHeartbeat _t) { target = _t; }

    function exploit(bytes calldata small) external {
        // request excessive len to leak beyond payload
        target.heartbeat(small, 0xFFFF);
    }
}

contract TLSSafeHeartbeat {
    bytes public lastPing;
    uint16 public constant MAX_LEN = 4096;
    event TLSDefended(address indexed who, TLSLayerType layer, TLSDefenseType defense);

    function heartbeat(bytes calldata payload, uint16 len) external {
        if (len > payload.length || len > MAX_LEN) revert TLS__OutOfBounds();
        lastPing = payload[:len];
        emit TLSDefended(msg.sender, TLSLayerType.Heartbeat, TLSDefenseType.BoundsCheck);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) RENEGOTIATION WITHOUT SECURE FLAG
//    • Vulnerable: allows renegotiation mid-session w/o verifying extension
//    • Attack: RenegSpoof injects malicious handshake
//    • Defense: require “secure_renegotiation” flag in extension
////////////////////////////////////////////////////////////////////////////////
contract TLSVulnRenegotiation {
    mapping(address => bool) public reneg;

    function renegotiate(address peer, bytes calldata ext) external {
        // ❌ no check for secure_renegotiation extension
        reneg[msg.sender] = true;
    }
}

contract Attack_TLSReneg {
    TLSVulnRenegotiation public target;
    constructor(TLSVulnRenegotiation _t) { target = _t; }

    function spoof() external {
        target.renegotiate(address(0xBEEF), "");
    }
}

contract TLSSafeRenegotiation {
    mapping(address => bool) public reneg;
    event TLSDefended(address indexed who, TLSLayerType layer, TLSDefenseType defense);

    /// ✅ require that ext includes the secure_renegotiation flag (0xFF)
    function renegotiate(address peer, bytes calldata ext) external {
        bool ok;
        for (uint i; i + 1 < ext.length; i++) {
            if (ext[i] == 0xFF) { ok = true; break; }
        }
        if (!ok) revert TLS__NotAllowed();
        reneg[msg.sender] = true;
        emit TLSDefended(msg.sender, TLSLayerType.Renegotiation, TLSDefenseType.SecureRenegotiation);
    }
}
