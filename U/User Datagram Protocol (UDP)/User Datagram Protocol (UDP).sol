// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title UserDiagramProtocolSuite.sol
/// @notice On‑chain analogues of “User Diagram Protocol” messaging patterns:
///   Types: Sequence, StateSync, Broadcast, EventDriven  
///   AttackTypes: SpoofStep, FloodDiagram, ReplayStep, OutOfOrder  
///   DefenseTypes: ValidateSource, RateLimit, NonceProtect, SequenceCheck  

enum UDPType             { Sequence, StateSync, Broadcast, EventDriven }
enum UDPAttackType       { SpoofStep, FloodDiagram, ReplayStep, OutOfOrder }
enum UDPDefenseType      { ValidateSource, RateLimit, NonceProtect, SequenceCheck }

error UDP__NotAllowed();
error UDP__TooMany();
error UDP__InvalidNonce();
error UDP__BadSequence();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE PROTOCOL (no source validation, no ordering)
///─────────────────────────────────────────────────────────────────────────────
contract UserDiagramProtocolVuln {
    event Step(
        address indexed user,
        uint256 indexed seq,
        string    action,
        UDPAttackType attack
    );

    /// ❌ anyone may emit any step with any user or sequence
    function sendStep(address user, uint256 seq, string calldata action) external {
        emit Step(user, seq, action, UDPAttackType.SpoofStep);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB (spoof & flood)
///─────────────────────────────────────────────────────────────────────────────
contract Attack_UserDiagramProtocol {
    UserDiagramProtocolVuln public target;

    constructor(UserDiagramProtocolVuln _t) { target = _t; }

    /// spoof steps as another user
    function spoof(address victim, uint256 seq, string calldata action) external {
        target.sendStep(victim, seq, action);
    }

    /// flood many actions to overwhelm consumers
    function flood(address user, uint256 startSeq, string calldata action, uint count) external {
        for (uint i = 0; i < count; i++) {
            target.sendStep(user, startSeq + i, action);
        }
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE PROTOCOL WITH SOURCE VALIDATION & RATE‑LIMIT
///─────────────────────────────────────────────────────────────────────────────
contract UserDiagramProtocolSafe {
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public countInBlock;
    uint256 public constant MAX_PER_BLOCK = 10;

    event Step(
        address indexed user,
        uint256 indexed seq,
        string    action,
        UDPDefenseType defense
    );

    /// ✅ only msg.sender may send its own steps, rate‑limited per block
    function sendStep(uint256 seq, string calldata action) external {
        // rate limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender] = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender]++;
        if (countInBlock[msg.sender] > MAX_PER_BLOCK) revert UDP__TooMany();

        emit Step(msg.sender, seq, action, UDPDefenseType.RateLimit);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE PROTOCOL WITH NONCE & SEQUENCE CHECK
///─────────────────────────────────────────────────────────────────────────────
contract UserDiagramProtocolSafeNonce {
    mapping(address => mapping(uint256 => bool)) public usedNonce;
    mapping(address => uint256) public lastSeq;

    event Step(
        address indexed user,
        uint256 indexed seq,
        string    action,
        UDPDefenseType defense
    );

    /// ✅ require unique nonce (seq) and monotonic sequence
    function sendStep(uint256 seq, string calldata action) external {
        // replay protection
        if (usedNonce[msg.sender][seq]) revert UDP__InvalidNonce();
        usedNonce[msg.sender][seq] = true;
        // sequence order enforcement
        if (seq != lastSeq[msg.sender] + 1) revert UDP__BadSequence();
        lastSeq[msg.sender] = seq;

        emit Step(msg.sender, seq, action, UDPDefenseType.SequenceCheck);
    }
}
