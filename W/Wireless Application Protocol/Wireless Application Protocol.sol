// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title WirelessApplicationProtocolSuite.sol
/// @notice On‑chain analogues of “Wireless Application Protocol” (WAP) message handling:
///   Types: WSP, WTP, WTLS, WDP  
///   AttackTypes: SpoofPacket, ReplayPacket, Flood, Downgrade  
///   DefenseTypes: Authenticate, NonceProtect, RateLimit, ProtocolEnforce  

enum WAPType           { WSP, WTP, WTLS, WDP }
enum WAPAttackType     { SpoofPacket, ReplayPacket, Flood, Downgrade }
enum WAPDefenseType    { Authenticate, NonceProtect, RateLimit, ProtocolEnforce }

error WAP__NotAllowed();
error WAP__InvalidNonce();
error WAP__TooMany();
error WAP__BadVersion();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE: accepts any PDU without auth or validation
///─────────────────────────────────────────────────────────────────────────────
contract WAPPDUVuln {
    event PDUReceived(
        address indexed from,
        WAPType        pduType,
        bytes          payload,
        WAPAttackType  attack
    );

    /// ❌ no checks, logs raw PDU
    function sendPDU(WAPType pduType, bytes calldata payload) external {
        emit PDUReceived(msg.sender, pduType, payload, WAPAttackType.SpoofPacket);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB: spoof, replay, flood, or downgrade attacks
///─────────────────────────────────────────────────────────────────────────────
contract Attack_WAPPDU {
    WAPPDUVuln public target;
    constructor(WAPPDUVuln _t) { target = _t; }

    /// spoof packet as another sender
    function spoof(address victim, WAPType t, bytes calldata p) external {
        // attacker pretends to be victim
        target.sendPDU(t, p);
    }

    /// replay previously captured payload
    function replay(WAPType t, bytes calldata p) external {
        target.sendPDU(t, p);
    }

    /// flood many PDUs in one call
    function flood(WAPType t, bytes calldata p, uint256 count) external {
        for (uint256 i = 0; i < count; i++) {
            target.sendPDU(t, p);
        }
    }

    /// downgrade: send using lower‑security type (e.g. WTLS→WTP)
    function downgrade(bytes calldata p) external {
        target.sendPDU(WAPType.WTP, p);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE: Authenticate senders & enforce protocol version
///─────────────────────────────────────────────────────────────────────────────
contract WAPPDUSafeAuth {
    mapping(address => bool) public allowed;
    mapping(WAPType => uint8) public version; // max supported version per PDU type
    address public owner;

    event PDUReceived(
        address indexed from,
        WAPType        pduType,
        bytes          payload,
        WAPDefenseType defense
    );

    constructor() { owner = msg.sender; }

    /// owner whitelists senders
    function setAllowed(address who, bool ok) external {
        if (msg.sender != owner) revert WAP__NotAllowed();
        allowed[who] = ok;
    }

    /// owner configures max supported versions
    function setVersion(WAPType t, uint8 v) external {
        if (msg.sender != owner) revert WAP__NotAllowed();
        version[t] = v;
    }

    /// ✅ only allowed senders, enforce protocol version in payload[0]
    function sendPDU(WAPType pduType, bytes calldata payload) external {
        if (!allowed[msg.sender]) revert WAP__NotAllowed();
        if (payload.length == 0 || payload[0] > version[pduType]) revert WAP__BadVersion();
        emit PDUReceived(msg.sender, pduType, payload, WAPDefenseType.Authenticate);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE: NonceProtect & RateLimit per block
///─────────────────────────────────────────────────────────────────────────────
contract WAPPDUSafeNonceRate {
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public countInBlock;
    mapping(address => mapping(uint256 => bool)) public usedNonce;
    uint256 public constant MAX_PER_BLOCK = 20;

    event PDUReceived(
        address indexed from,
        WAPType        pduType,
        bytes          payload,
        WAPDefenseType defense,
        uint256        nonce
    );

    /// ✅ require unique nonce and cap PDUs per block per sender
    function sendPDU(WAPType pduType, bytes calldata payload, uint256 nonce) external {
        // rate‑limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender] = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender]++;
        if (countInBlock[msg.sender] > MAX_PER_BLOCK) revert WAP__TooMany();

        // replay protection
        if (usedNonce[msg.sender][nonce]) revert WAP__InvalidNonce();
        usedNonce[msg.sender][nonce] = true;

        emit PDUReceived(msg.sender, pduType, payload, WAPDefenseType.NonceProtect, nonce);
    }
}
