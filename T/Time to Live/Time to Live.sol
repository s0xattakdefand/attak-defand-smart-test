// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title TimeToLiveSuite.sol
/// @notice On-chain analogues of “Time To Live (TTL)” patterns:
///   Types: DNSTTL, SessionTTL, CacheTTL, PacketTTL
///   AttackTypes: ExpiryBypass, TTLOverflow, TTLUnderflow
///   DefenseTypes: EnforceTTL, AutoExpire, TTLValidation

error TTL__Expired();
error TTL__Overflow();
error TTL__Underflow();

///─────────────────────────────────────────────────────────────────────────────
/// Type definitions
///─────────────────────────────────────────────────────────────────────────────
enum TTLType         { DNSTTL, SessionTTL, CacheTTL, PacketTTL }
enum TTLAttackType   { ExpiryBypass, TTLOverflow, TTLUnderflow }
enum TTLDefenseType  { EnforceTTL, AutoExpire, TTLValidation }

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE TTL STORE
///    • no enforcement of expiry or overflow checks
///    • Attack: bypass expiry by calling use() regardless of TTL
///─────────────────────────────────────────────────────────────────────────────
contract TTLVuln {
    mapping(uint256 => uint256) public expiry;
    event Action(uint256 indexed id, TTLType tType, TTLAttackType attack);

    /// anyone may set arbitrary TTL
    function setTTL(uint256 id, uint256 ttl) external {
        expiry[id] = block.timestamp + ttl;
    }

    /// uses resource without checking TTL
    function use(uint256 id) external {
        emit Action(id, TTLType.SessionTTL, TTLAttackType.ExpiryBypass);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB
///    • demonstrates expiry bypass by calling use() after TTL
///─────────────────────────────────────────────────────────────────────────────
contract Attack_TTL {
    TTLVuln public target;
    constructor(TTLVuln _t) { target = _t; }

    function bypass(uint256 id, uint256 ttl) external {
        target.setTTL(id, ttl);
        // off-chain simulate waiting past TTL, then call:
        target.use(id);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE TTL STORE
///    • enforces overflow, underflow, expiry checks, and auto-cleanup
///─────────────────────────────────────────────────────────────────────────────
contract TTLSafe {
    mapping(uint256 => uint256) public expiry;
    event Action(uint256 indexed id, TTLType tType, TTLDefenseType defense);

    /// set TTL with overflow/underflow validation
    function setTTL(uint256 id, uint256 ttl) external {
        if (ttl > 365 days) revert TTL__Overflow();
        uint256 exp = block.timestamp + ttl;
        if (exp < block.timestamp) revert TTL__Underflow();
        expiry[id] = exp;
        emit Action(id, TTLType.SessionTTL, TTLDefenseType.TTLValidation);
    }

    /// use only if not expired
    function use(uint256 id) external {
        uint256 exp = expiry[id];
        if (exp == 0 || block.timestamp > exp) revert TTL__Expired();
        emit Action(id, TTLType.SessionTTL, TTLDefenseType.EnforceTTL);
    }

    /// optional: auto-expire cleanup
    function cleanup(uint256 id) external {
        if (expiry[id] != 0 && block.timestamp > expiry[id]) {
            delete expiry[id];
            emit Action(id, TTLType.SessionTTL, TTLDefenseType.AutoExpire);
        }
    }
}
