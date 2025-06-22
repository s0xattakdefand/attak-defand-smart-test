// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DayZeroSuite.sol
/// @notice On‑chain analogues of “Day Zero” vulnerability patterns:
///   Types: Software, Firmware, Configuration, SupplyChain  
///   AttackTypes: RemoteExploit, PrivilegeEscalation, WormPropagation, DataExfiltration  
///   DefenseTypes: PatchManagement, IntrusionDetection  

enum DayZeroType             { Software, Firmware, Configuration, SupplyChain }
enum DayZeroAttackType       { RemoteExploit, PrivilegeEscalation, WormPropagation, DataExfiltration }
enum DayZeroDefenseType      { PatchManagement, IntrusionDetection }

error DZ__AlreadyPatched();
error DZ__NoPatch();
error DZ__TooManyAttempts();

////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE “Day Zero” EXPLOITATION
//
//    • no patching or detection → free to exploit any target  
//    • AttackType: RemoteExploit, WormPropagation, etc.
////////////////////////////////////////////////////////////////////////
contract DayZeroVuln {
    event Exploited(
        address indexed attacker,
        uint256 indexed targetId,
        DayZeroType    dzType,
        DayZeroAttackType attack
    );

    /// ❌ anyone may exploit any target at will
    function exploit(uint256 targetId, DayZeroType dzType) external {
        emit Exploited(msg.sender, targetId, dzType, DayZeroAttackType.RemoteExploit);
    }
}

////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB: chain‐exploit & self‐propagate
//
//    • combine exploits and propagate like a worm
////////////////////////////////////////////////////////////////////////
contract Attack_DayZero {
    DayZeroVuln public target;
    constructor(DayZeroVuln _t) { target = _t; }

    /// chain two exploits in one call
    function multiExploit(uint256 idA, uint256 idB) external {
        target.exploit(idA, DayZeroType.Software);
        target.exploit(idB, DayZeroType.Firmware);
    }

    /// worm‑style propagation across targets
    function propagate(uint256[] calldata ids) external {
        for (uint i = 0; i < ids.length; i++) {
            target.exploit(ids[i], DayZeroType.Configuration);
        }
    }
}

////////////////////////////////////////////////////////////////////////
// 3) SAFE PATCH MANAGEMENT
//
//    • Defense: PatchManagement – only owner may patch, one‑time per target  
////////////////////////////////////////////////////////////////////////
contract DayZeroSafePatch {
    address public owner;
    mapping(uint256 => bool) public patched;
    event PatchApplied(
        uint256 indexed targetId,
        DayZeroType    dzType,
        DayZeroDefenseType defense
    );
    error DZ__NotOwner();
    error DZ__AlreadyPatched();

    constructor() { owner = msg.sender; }

    /// ✅ owner applies patch exactly once per target
    function applyPatch(uint256 targetId, DayZeroType dzType) external {
        if (msg.sender != owner)           revert DZ__NotOwner();
        if (patched[targetId])             revert DZ__AlreadyPatched();
        patched[targetId] = true;
        emit PatchApplied(targetId, dzType, DayZeroDefenseType.PatchManagement);
    }

    /// patched targets cannot be exploited
    function exploit(uint256 targetId, DayZeroType dzType) external view {
        if (patched[targetId]) revert DZ__AlreadyPatched();
        // otherwise exploitation would proceed off‑chain
    }
}

////////////////////////////////////////////////////////////////////////
// 4) SAFE INTRUSION DETECTION (RATE‑LIMITED)
//  
//    • Defense: IntrusionDetection – log and cap exploit attempts  
////////////////////////////////////////////////////////////////////////
contract DayZeroSafeIDS {
    mapping(uint256 => uint256) public attempts;
    uint256 public constant MAX_ATTEMPTS = 5;
    event IntrusionDetected(
        address indexed attacker,
        uint256 indexed targetId,
        DayZeroType    dzType,
        DayZeroDefenseType defense
    );
    error DZ__TooManyAttempts();

    /// ✅ detect and rate‑limit exploit attempts per target
    function exploit(uint256 targetId, DayZeroType dzType) external {
        attempts[targetId]++;
        if (attempts[targetId] > MAX_ATTEMPTS) revert DZ__TooManyAttempts();
        emit IntrusionDetected(msg.sender, targetId, dzType, DayZeroDefenseType.IntrusionDetection);
    }
}
