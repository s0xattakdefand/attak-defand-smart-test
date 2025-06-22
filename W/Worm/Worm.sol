// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title WormSuite.sol
/// @notice Four on‑chain “Worm” propagation patterns illustrating common pitfalls
///         and hardened defenses.

enum WormType         { FileInfect, NetworkPropagate, EmailSpread, SocialSpread }
enum WormAttackType   { SelfReplicate, PayloadDeploy, Mutate, StealthInjection }
enum WormDefenseType  { AuthGuard, RateLimit, ImmutableOnce, Quarantine }

error WRM__NotOwner();
error WRM__TooManyInfections();
error WRM__AlreadyPatched();
error WRM__Quarantined();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE WORM PROPAGATION
///
///    • no access control, no limits, no patching → unchecked spread
///    • AttackType: SelfReplicate
///─────────────────────────────────────────────────────────────────────────────
contract WormVuln {
    mapping(address => bool) public infected;
    event Infected(address indexed by, address indexed target, WormAttackType attack);

    /// ❌ anyone may infect any target arbitrarily
    function infect(address target) external {
        infected[target] = true;
        emit Infected(msg.sender, target, WormAttackType.SelfReplicate);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB
///
///    • floods many targets in one call
///─────────────────────────────────────────────────────────────────────────────
contract Attack_Worm {
    WormVuln public worm;
    constructor(WormVuln _worm) { worm = _worm; }

    /// attacker replicates the worm to a list of victims
    function replicate(address[] calldata targets) external {
        for (uint i; i < targets.length; i++) {
            worm.infect(targets[i]);
        }
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE PROPAGATION WITH AUTHORIZATION
///
///    • Defense: AuthGuard – only owner may call infect
///─────────────────────────────────────────────────────────────────────────────
contract WormSafeAuth {
    mapping(address => bool) public infected;
    address public owner;
    event Infected(address indexed by, address indexed target, WormDefenseType defense);

    constructor() { owner = msg.sender; }

    /// ✅ only owner may spread the “worm”
    function infect(address target) external {
        if (msg.sender != owner) revert WRM__NotOwner();
        infected[target] = true;
        emit Infected(msg.sender, target, WormDefenseType.AuthGuard);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE PROPAGATION WITH RATE‑LIMITING & IMMUTABLE PATCH
///
///    • Defense: RateLimit – cap infections per block  
///                ImmutableOnce – once patched, cannot be reinfected  
///─────────────────────────────────────────────────────────────────────────────
contract WormSafeRateLimit {
    mapping(address => bool)   public infected;
    mapping(address => bool)   public patched;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public infectionsInBlock;
    uint256 public constant MAX_INFECT_PER_BLOCK = 5;
    event Infected(address indexed by, address indexed target, WormDefenseType defense);
    event Patched(address indexed target, WormDefenseType defense);

    /// infect a target, rate‑limited per sender and skip already patched
    function infect(address target) external {
        // immutable patch prevents reinfection
        if (patched[target]) revert WRM__AlreadyPatched();

        // rate‑limit per sender per block
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender] = block.number;
            infectionsInBlock[msg.sender] = 0;
        }
        infectionsInBlock[msg.sender]++;
        if (infectionsInBlock[msg.sender] > MAX_INFECT_PER_BLOCK) {
            revert WRM__TooManyInfections();
        }

        infected[target] = true;
        emit Infected(msg.sender, target, WormDefenseType.RateLimit);
    }

    /// quarantine (patch) a target to prevent further infection
    function quarantine(address target) external {
        // anyone can quarantine (e.g. security team)
        patched[target] = true;
        emit Patched(target, WormDefenseType.Quarantine);
    }
}
