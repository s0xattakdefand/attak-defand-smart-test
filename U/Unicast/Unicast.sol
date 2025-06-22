// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title UnicastSuite.sol
/// @notice On‑chain analogues of “Unicast” messaging patterns:
///   Types: Basic, Spoofable, Floodable, Replayable  
///   AttackTypes: SpoofSender, FloodMessage, ReplayMessage  
///   DefenseTypes: SenderValidation, RateLimit, NonceProtect  

enum UnicastType         { Basic, Spoofable, Floodable, Replayable }
enum UnicastAttackType   { SpoofSender, FloodMessage, ReplayMessage }
enum UnicastDefenseType  { SenderValidation, RateLimit, NonceProtect }

error UC__NotAllowed();
error UC__TooMany();
error UC__InvalidNonce();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE UNICAST (no validation, no limits, no replay protection)
///─────────────────────────────────────────────────────────────────────────────
contract UnicastVuln {
    event Message(
        address indexed from,
        address indexed to,
        bytes          data,
        UnicastAttackType  attack
    );

    /// ❌ anyone may claim any sender, flood, or replay messages
    function send(
        address from,
        address to,
        bytes calldata data
    ) external {
        emit Message(from, to, data, UnicastAttackType.SpoofSender);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB: spoof and flood unicast
///─────────────────────────────────────────────────────────────────────────────
contract Attack_Unicast {
    UnicastVuln public target;
    constructor(UnicastVuln _t) { target = _t; }

    /// spoof as victim
    function spoof(
        address victim,
        address to,
        bytes calldata data
    ) external {
        target.send(victim, to, data);
    }

    /// flood messages from attacker’s address
    function flood(
        address to,
        bytes calldata data,
        uint256 count
    ) external {
        for (uint256 i = 0; i < count; i++) {
            target.send(msg.sender, to, data);
        }
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE UNICAST WITH SENDER VALIDATION (default deny)
///─────────────────────────────────────────────────────────────────────────────
contract UnicastSafeValidation {
    mapping(address => bool) public allowed;
    address public owner;
    event Message(
        address indexed from,
        address indexed to,
        bytes          data,
        UnicastDefenseType defense
    );

    constructor() { owner = msg.sender; }

    /// only owner may whitelist senders
    function setAllowed(address who, bool ok) external {
        if (msg.sender != owner) revert UC__NotAllowed();
        allowed[who] = ok;
    }

    /// ✅ only allowed senders, msg.sender as source
    function send(address to, bytes calldata data) external {
        if (!allowed[msg.sender]) revert UC__NotAllowed();
        emit Message(msg.sender, to, data, UnicastDefenseType.SenderValidation);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE UNICAST WITH RATE‑LIMIT & REPLAY PROTECTION
///─────────────────────────────────────────────────────────────────────────────
contract UnicastSafeRateLimitNonce {
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public countInBlock;
    mapping(address => mapping(uint256 => bool)) public usedNonce;
    uint256 public constant MAX_PER_BLOCK = 10;

    event Message(
        address indexed from,
        address indexed to,
        bytes          data,
        UnicastDefenseType defense,
        uint256        nonce
    );

    /// ✅ rate‑limit per block and require unique nonce per sender
    function send(
        address to,
        bytes calldata data,
        uint256 nonce
    ) external {
        // reset counter at new block
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender] = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender] += 1;
        if (countInBlock[msg.sender] > MAX_PER_BLOCK) revert UC__TooMany();

        // prevent replay
        if (usedNonce[msg.sender][nonce]) revert UC__InvalidNonce();
        usedNonce[msg.sender][nonce] = true;

        emit Message(msg.sender, to, data, UnicastDefenseType.RateLimit, nonce);
    }
}
