// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title WebOfTrustSuite.sol
/// @notice On‑chain analogues of “Web of Trust” patterns:
///   Types: DirectTrust, TransitiveTrust, Revocation  
///   AttackTypes: SybilAttack, TrustFlood, ManInTheMiddle  
///   DefenseTypes: IdentityValidation, RateLimit, ReputationThreshold  

enum WebOfTrustType         { DirectTrust, TransitiveTrust, Revocation }
enum WebOfTrustAttackType   { SybilAttack, TrustFlood, ManInTheMiddle }
enum WebOfTrustDefenseType  { IdentityValidation, RateLimit, ReputationThreshold }

error WOT__TooMany();
error WOT__NotAllowed();
error WOT__LowReputation();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE TRUST REGISTRY
///
///    • anyone may vouch for any pair (no validation)
///    • Attack: Sybil nodes create arbitrary trust edges
///─────────────────────────────────────────────────────────────────────────────
contract WebOfTrustVuln {
    // mapping[truster][trustee] => true if vouched
    mapping(address => mapping(address => bool)) public trusts;
    event Vouched(
        address indexed truster,
        address indexed trustee,
        WebOfTrustType       kind,
        WebOfTrustAttackType attack
    );

    /// ❌ no validation: arbitrary truster/trustee allowed
    function vouch(address truster, address trustee, WebOfTrustType kind) external {
        trusts[truster][trustee] = true;
        emit Vouched(truster, trustee, kind, WebOfTrustAttackType.SybilAttack);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB
///
///    • trustFlood: attacker floods many vouches from itself
///─────────────────────────────────────────────────────────────────────────────
contract Attack_WebOfTrust {
    WebOfTrustVuln public target;
    constructor(WebOfTrustVuln _t) { target = _t; }

    /// flood‑vouch multiple trustees
    function trustFlood(address[] calldata trustees) external {
        for (uint i = 0; i < trustees.length; i++) {
            target.vouch(msg.sender, trustees[i], WebOfTrustType.DirectTrust);
        }
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE DIRECT TRUST
///
///    • Defense: IdentityValidation – only msg.sender may vouch for others
///─────────────────────────────────────────────────────────────────────────────
contract WebOfTrustSafe {
    mapping(address => mapping(address => bool)) public trusts;
    event Vouched(
        address indexed truster,
        address indexed trustee,
        WebOfTrustType       kind,
        WebOfTrustDefenseType defense
    );

    /// ✅ validate identity: truster must be msg.sender
    function vouch(address trustee, WebOfTrustType kind) external {
        trusts[msg.sender][trustee] = true;
        emit Vouched(msg.sender, trustee, kind, WebOfTrustDefenseType.IdentityValidation);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) RATE‑LIMITED TRUST & REPUTATION THRESHOLD
///
///    • Defense: RateLimit – cap vouches per block  
///               ReputationThreshold – only vouch if truster sufficiently trusted  
///─────────────────────────────────────────────────────────────────────────────
contract WebOfTrustSafeAdvanced {
    mapping(address => mapping(address => bool)) public trusts;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public countInBlock;
    mapping(address => uint256) public reputation; // count of incoming vouches
    uint256 public constant MAX_VOUCH_PER_BLOCK = 5;
    uint256 public constant MIN_REPUTATION = 3;

    event Vouched(
        address indexed truster,
        address indexed trustee,
        WebOfTrustType       kind,
        WebOfTrustDefenseType defense
    );

    error WOT__TooMany();
    error WOT__LowReputation();

    /// anyone can be vouched for; reputation updated on each vouch
    function _incrementReputation(address trustee) internal {
        reputation[trustee]++;
    }

    /// vouch with rate‑limit and threshold checks
    function vouch(address trustee, WebOfTrustType kind) external {
        // rate‑limit per block
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender] = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender]++;
        if (countInBlock[msg.sender] > MAX_VOUCH_PER_BLOCK) revert WOT__TooMany();

        // reputation threshold: truster must have >= MIN_REPUTATION incoming vouches
        if (reputation[msg.sender] < MIN_REPUTATION) revert WOT__LowReputation();

        trusts[msg.sender][trustee] = true;
        _incrementReputation(trustee);
        emit Vouched(msg.sender, trustee, kind, WebOfTrustDefenseType.RateLimit);
    }
}
