// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title TinyFragmentSuite.sol
/// @notice On-chain analogues of the classic "Tiny Fragment" attack
///   Types: FragmentationType
///   AttackTypes: TinyFragmentAttack
///   DefenseTypes: MinFragmentSize

error TF__FragTooSmall();
error TF__NotAllowed();

///─────────────────────────────────────────────────────────────────────────────
/// Type definitions
///─────────────────────────────────────────────────────────────────────────────
enum FragmentationType      { IPv4, IPv6 }
enum TinyFragmentAttackType { TinyFragmentation }
enum TinyFragmentDefenseType{ MinFragmentSize }

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE REASSEMBLY MODULE
///    • no enforcement of minimum fragment size
///    • Attack: split header across tiny fragments to bypass filters
///─────────────────────────────────────────────────────────────────────────────
contract TinyFragmentVuln {
    mapping(uint16 => bytes) public reassembly;
    event FragmentReceived(uint16 indexed id, bytes data);

    /// store incoming fragment without any size checks
    function fragment(uint16 id, bytes calldata frag) external {
        reassembly[id] = bytes.concat(reassembly[id], frag);
        emit FragmentReceived(id, frag);
    }

    /// return full reassembled data
    function assemble(uint16 id) external view returns (bytes memory) {
        return reassembly[id];
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB
///    • demonstrates sending tiny fragments to evade inspection
///─────────────────────────────────────────────────────────────────────────────
contract Attack_TinyFragment {
    TinyFragmentVuln public target;
    constructor(TinyFragmentVuln _t) { target = _t; }

    /// send two tiny fragments, each smaller than typical filter threshold (e.g., <8 bytes)
    function sendTiny(uint16 id, bytes calldata headerPart1, bytes calldata headerPart2) external {
        // headerPart1 and headerPart2 might each be just 3 bytes, splitting critical header fields
        target.fragment(id, headerPart1);
        target.fragment(id, headerPart2);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) DEFENSE MODULE
///    • enforce minimum fragment size to prevent tiny-fragment attacks
///─────────────────────────────────────────────────────────────────────────────
contract TinyFragmentSafe {
    mapping(uint16 => bytes) public reassembly;
    event FragmentAccepted(uint16 indexed id, bytes data, TinyFragmentDefenseType defense);

    uint256 public constant MIN_FRAG_SIZE = 8;  // require at least 8 bytes per fragment

    /// only accept fragments meeting the minimum size
    function fragment(uint16 id, bytes calldata frag) external {
        if (frag.length < MIN_FRAG_SIZE) revert TF__FragTooSmall();
        reassembly[id] = bytes.concat(reassembly[id], frag);
        emit FragmentAccepted(id, frag, TinyFragmentDefenseType.MinFragmentSize);
    }

    /// return reassembled data
    function assemble(uint16 id) external view returns (bytes memory) {
        return reassembly[id];
    }
}
