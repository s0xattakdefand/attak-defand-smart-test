// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title BacktrackingResistanceSuite.sol
/// @notice On-chain analogues of “Backtracking Resistance” in random-state schemes:
///   Types: HashChain, PRFBased, DRBGBased  
///   AttackTypes: StateCompromise, KeyRecovery, ReplayAttack  
///   DefenseTypes: OneWayUpdate, ForwardSecurity, SeedRefresh  

enum BacktrackingResistanceType       { HashChain, PRFBased, DRBGBased }
enum BacktrackingResistanceAttackType { StateCompromise, KeyRecovery, ReplayAttack }
enum BacktrackingResistanceDefenseType{ OneWayUpdate, ForwardSecurity, SeedRefresh }

error BR__InvalidSeed();
error BR__Compromised();
error BR__TooFrequent();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE HASH-CHAIN RNG
///
///    • stores last output and reuses it → KeyRecovery  
///    • Attack: state compromise yields all past/future outputs
///─────────────────────────────────────────────────────────────────────────────
contract BRVulnHashChain {
    bytes32 public state;

    event Random(
        address indexed who,
        bytes32           out,
        BacktrackingResistanceAttackType attack
    );

    /// initialize seed
    function initialize(bytes32 seed) external {
        state = seed;
    }

    /// ❌ simply returns state and leaves it unchanged
    function random() external returns (bytes32 out) {
        out = state;
        emit Random(msg.sender, out, BacktrackingResistanceAttackType.KeyRecovery);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB
///
///    • captures state and replays past/future outputs
///─────────────────────────────────────────────────────────────────────────────
contract Attack_BRHashChain {
    BRVulnHashChain public target;
    bytes32 public captured;

    constructor(BRVulnHashChain _t) { target = _t; }

    /// capture current state
    function capture() external {
        captured = target.state();
    }

    /// replay using captured state
    function replay() external {
        // attacker calls random() having stolen state
        target.random();
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE HASH-CHAIN WITH ONE-WAY UPDATE
///
///    • Defense: OneWayUpdate – state = keccak256(prev) each call
///─────────────────────────────────────────────────────────────────────────────
contract BRSafeHashChain {
    bytes32 private state;

    event Random(
        address indexed who,
        bytes32           out,
        BacktrackingResistanceDefenseType defense
    );

    function initialize(bytes32 seed) external {
        state = seed;
    }

    /// ✅ one-way update prevents backtracking
    function random() external returns (bytes32 out) {
        out = keccak256(abi.encodePacked(state));
        state = out;
        emit Random(msg.sender, out, BacktrackingResistanceDefenseType.OneWayUpdate);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE PRF-BASED RNG WITH FORWARD-SECURITY
///
///    • Defense: ForwardSecurity – derive new key and erase old
///─────────────────────────────────────────────────────────────────────────────
contract BRSafePRF {
    bytes32 private key;

    event Random(
        address indexed who,
        bytes32           out,
        BacktrackingResistanceDefenseType defense
    );

    function initialize(bytes32 k0) external {
        key = k0;
    }

    /// ✅ uses HMAC-style PRF and rotates key
    function random(bytes32 input) external returns (bytes32 out) {
        // stub PRF: keccak256(key || input)
        out = keccak256(abi.encodePacked(key, input));
        // forward-secure key update: key = H(key)
        key = keccak256(abi.encodePacked(key));
        emit Random(msg.sender, out, BacktrackingResistanceDefenseType.ForwardSecurity);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 5) SAFE DRBG-BASED WITH SEED REFRESH & RATE-LIMIT
///
///    • Defense: SeedRefresh – periodically re-seed from entropy source  
///               RateLimit – cap calls to prevent state exhaustion
///─────────────────────────────────────────────────────────────────────────────
contract BRSafeDRBG {
    bytes32 private state;
    uint256 public lastCallBlock;
    uint256 public constant MAX_CALLS_PER_BLOCK = 5;

    event Random(
        address indexed who,
        bytes32           out,
        BacktrackingResistanceDefenseType defense
    );

    error BR__TooFrequent();

    function initialize(bytes32 seed) external {
        state = seed;
    }

    /// stub entropy source
    function _entropy() internal view returns (bytes32) {
        return keccak256(abi.encodePacked(blockhash(block.number - 1), block.timestamp));
    }

    function random() external returns (bytes32 out) {
        // rate-limit per block
        if (block.number == lastCallBlock) {
            revert BR__TooFrequent();
        }
        lastCallBlock = block.number;

        // DRBG: out = H(state || ctr), here ctr = block.number
        out = keccak256(abi.encodePacked(state, block.number));
        // seed refresh: state = H(state || entropy)
        state = keccak256(abi.encodePacked(state, _entropy()));
        emit Random(msg.sender, out, BacktrackingResistanceDefenseType.SeedRefresh);
    }
}
