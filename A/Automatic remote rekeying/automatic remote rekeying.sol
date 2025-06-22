// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AutomaticRemoteRekeyingSuite.sol
/// @notice On-chain analogues of “Automatic Remote Rekeying” patterns:
///   Types: Periodic, OnDemand, EventDriven  
///   AttackTypes: MITM, Replay, KeyExfiltration  
///   DefenseTypes: KeyRotation, AuthChallenge, SecureChannel, NonceValidation  

enum RekeyType             { Periodic, OnDemand, EventDriven }
enum RekeyAttackType       { MITM, Replay, KeyExfiltration }
enum RekeyDefenseType      { KeyRotation, AuthChallenge, SecureChannel, NonceValidation }

error ARK__NotOwner();
error ARK__InvalidNonce();
error ARK__AuthFailed();
error ARK__TooFrequent();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE REKEY SERVICE
///
///    • no authentication or freshness on rekey → MITM, Replay
///─────────────────────────────────────────────────────────────────────────────
contract AutomaticRemoteRekeyingVuln {
    bytes32 public currentKey;
    event Rekeyed(
        address       indexed by,
        RekeyType                rtype,
        bytes32                  newKey,
        RekeyAttackType          attack
    );

    function rekey(RekeyType rtype, bytes32 newKey) external {
        // ❌ no checks: anyone may overwrite the key
        currentKey = newKey;
        emit Rekeyed(msg.sender, rtype, newKey, RekeyAttackType.MITM);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB
///
///    • captures new keys, replays old key to reset
///─────────────────────────────────────────────────────────────────────────────
contract Attack_AutomaticRemoteRekeying {
    AutomaticRemoteRekeyingVuln public target;
    bytes32 public capturedKey;

    constructor(AutomaticRemoteRekeyingVuln _t) {
        target = _t;
    }

    function stealKey(RekeyType rtype, bytes32 newKey) external {
        target.rekey(rtype, newKey);
        capturedKey = newKey;
    }

    function replayOld(RekeyType rtype) external {
        // replay last captured key
        target.rekey(rtype, capturedKey);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE WITH AUTH CHALLENGE & NONCE VALIDATION
///
///    • Defense: AuthChallenge – require owner signature  
///               NonceValidation – prevent replay
///─────────────────────────────────────────────────────────────────────────────
contract AutomaticRemoteRekeyingSafeAuth {
    address public owner;
    bytes32 public currentKey;
    mapping(uint256 => bool) public usedNonces;

    event Rekeyed(
        address       indexed by,
        RekeyType                rtype,
        bytes32                  newKey,
        RekeyDefenseType         defense
    );

    error ARK__Replay();

    constructor(bytes32 initialKey) {
        owner = msg.sender;
        currentKey = initialKey;
    }

    /// owner signs (newKey||nonce)
    function rekey(
        RekeyType rtype,
        bytes32 newKey,
        uint256 nonce,
        bytes calldata sig
    ) external {
        if (usedNonces[nonce]) revert ARK__Replay();
        usedNonces[nonce] = true;

        bytes32 msgHash = keccak256(abi.encodePacked(newKey, nonce));
        bytes32 ethMsg  = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8, bytes32, bytes32));
        address signer = ecrecover(ethMsg, v, r, s);
        if (signer != owner) revert ARK__AuthFailed();

        currentKey = newKey;
        emit Rekeyed(msg.sender, rtype, newKey, RekeyDefenseType.AuthChallenge);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE WITH PERIODIC KEY ROTATION
///
///    • Defense: KeyRotation – auto-rotate every interval  
///               NonceValidation – one per period
///─────────────────────────────────────────────────────────────────────────────
contract AutomaticRemoteRekeyingSafePeriodic {
    bytes32 public currentKey;
    uint256 public lastRotation;
    uint256 public rotationInterval;
    mapping(uint256 => bool) public usedPeriods;

    event Rekeyed(
        address       indexed by,
        RekeyType                rtype,
        bytes32                  newKey,
        RekeyDefenseType         defense
    );

    error ARK__TooFrequent();

    constructor(bytes32 initialKey, uint256 interval) {
        currentKey = initialKey;
        rotationInterval = interval;
        lastRotation = block.timestamp;
    }

    /// anyone may trigger periodic rotation, but only once per interval
    function rotate(bytes32 newKey) external {
        uint256 period = block.timestamp / rotationInterval;
        if (usedPeriods[period]) revert ARK__TooFrequent();
        usedPeriods[period] = true;

        currentKey = newKey;
        lastRotation = block.timestamp;
        emit Rekeyed(msg.sender, RekeyType.Periodic, newKey, RekeyDefenseType.KeyRotation);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 5) SAFE ADVANCED WITH SECURE CHANNEL & EVENT-DRIVEN
///
///    • Defense: SecureChannel – whitelist callers  
///               EventDriven – rekey on external event
///─────────────────────────────────────────────────────────────────────────────
contract AutomaticRemoteRekeyingSafeAdvanced {
    bytes32 public currentKey;
    address public owner;
    mapping(address => bool) public allowedSenders;

    event Rekeyed(
        address       indexed by,
        RekeyType                rtype,
        bytes32                  newKey,
        RekeyDefenseType         defense
    );

    error ARK__NotAllowed();

    constructor(bytes32 initialKey) {
        owner = msg.sender;
        currentKey = initialKey;
        allowedSenders[msg.sender] = true;
    }

    function setAllowed(address who, bool ok) external {
        require(msg.sender == owner, "only owner");
        allowedSenders[who] = ok;
    }

    /// event-driven rekey: only allowed senders may call
    function rekeyEvent(bytes32 newKey) external {
        if (!allowedSenders[msg.sender]) revert ARK__NotAllowed();
        currentKey = newKey;
        emit Rekeyed(msg.sender, RekeyType.EventDriven, newKey, RekeyDefenseType.SecureChannel);
    }
}
