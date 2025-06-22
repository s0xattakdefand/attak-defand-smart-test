// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title WindowingSuite.sol
/// @notice On‑chain analogues of “Windowing” flow‑control patterns:
///   Types: Sliding, Tumbling  
///   AttackTypes: OversizeWindow, SequenceWrap  
///   DefenseTypes: WindowLimit, SequenceValidation  

enum WindowingType           { Sliding, Tumbling }
enum WindowingAttackType     { OversizeWindow, SequenceWrap }
enum WindowingDefenseType    { WindowLimit, SequenceValidation }

error WG__WindowTooLarge();
error WG__BadSequence();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE SLIDING WINDOW
///
///    • no limit on window size  
///    • no sequence checks  
///    • Attack: set huge window or wrap seq  
///─────────────────────────────────────────────────────────────────────────────
contract WindowingVuln {
    mapping(address => uint256) public windowSize;
    mapping(address => uint256) public lastSeq;

    event WindowSet(address indexed who, uint256 size, WindowingAttackType attack);
    event SegmentSent(address indexed who, uint256 seq, WindowingAttackType attack);

    function setWindow(uint256 size) external {
        windowSize[msg.sender] = size;
        emit WindowSet(msg.sender, size, WindowingAttackType.OversizeWindow);
    }

    function sendSegment(uint256 seq) external {
        // ❌ no sequence or window checks
        lastSeq[msg.sender] = seq;
        emit SegmentSent(msg.sender, seq, WindowingAttackType.SequenceWrap);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB: oversize window & wraparound
///
///    • AttackType: OversizeWindow, SequenceWrap  
///─────────────────────────────────────────────────────────────────────────────
contract Attack_Windowing {
    WindowingVuln public target;
    constructor(WindowingVuln _t) { target = _t; }

    function exploitOversize(uint256 hugeWindow) external {
        target.setWindow(hugeWindow);
    }

    function exploitWrap(uint256 seq) external {
        target.sendSegment(seq);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE WINDOW LIMIT
///
///    • enforce MAX_WINDOW  
///    • still no sequence validation  
///    • Defense: WindowLimit  
///─────────────────────────────────────────────────────────────────────────────
contract WindowingSafe {
    uint256 public constant MAX_WINDOW = 1024;
    mapping(address => uint256) public windowSize;
    mapping(address => uint256) public lastSeq;

    event WindowSet(address indexed who, uint256 size, WindowingDefenseType defense);
    event SegmentSent(address indexed who, uint256 seq, WindowingDefenseType defense);

    function setWindow(uint256 size) external {
        if (size > MAX_WINDOW) revert WG__WindowTooLarge();
        windowSize[msg.sender] = size;
        emit WindowSet(msg.sender, size, WindowingDefenseType.WindowLimit);
    }

    function sendSegment(uint256 seq) external {
        // ❌ sequence still unchecked
        lastSeq[msg.sender] = seq;
        emit SegmentSent(msg.sender, seq, WindowingDefenseType.WindowLimit);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE SEQUENCE VALIDATION
///
///    • enforce both window limit and monotonic sequence  
///    • Defense: SequenceValidation  
///─────────────────────────────────────────────────────────────────────────────
contract WindowingSafeSequence {
    uint256 public constant MAX_WINDOW = 1024;
    mapping(address => uint256) public windowSize;
    mapping(address => uint256) public lastSeq;

    event WindowSet(address indexed who, uint256 size, WindowingDefenseType defense);
    event SegmentAccepted(address indexed who, uint256 seq, WindowingDefenseType defense);

    function setWindow(uint256 size) external {
        if (size > MAX_WINDOW) revert WG__WindowTooLarge();
        windowSize[msg.sender] = size;
        emit WindowSet(msg.sender, size, WindowingDefenseType.WindowLimit);
    }

    function sendSegment(uint256 seq) external {
        uint256 win  = windowSize[msg.sender];
        uint256 prev = lastSeq[msg.sender];
        // ✅ require seq ∈ (prev, prev + win]
        if (seq <= prev || seq > prev + win) revert WG__BadSequence();
        lastSeq[msg.sender] = seq;
        emit SegmentAccepted(msg.sender, seq, WindowingDefenseType.SequenceValidation);
    }
}
