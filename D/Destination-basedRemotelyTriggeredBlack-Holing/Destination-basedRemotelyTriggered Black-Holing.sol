// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/* OpenZeppelin v5 */
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title Destination-based RTBH Registry
 *
 * Implements an on-chain registry for Remotely Triggered Black-Hol­ing rules.
 * Each entry = {IPv4 destination prefix, prefix-length, expiryTimestamp}.
 *
 * Off-chain BGP controller listens to events & programs routers accordingly.
 *
 *   addBlackhole(203.0.113.7/32,  1 hour,  "DDoS mitigation")
 *   addBlackhole(198.51.100.0/24, 4 hours, "Malware sinkhole")
 *
 * Authorised operators can also remove early (e.g. false-positive).
 */
contract RTBHRegistry is
    AccessControl,
    Ownable,
    Pausable,
    ReentrancyGuard
{
    /* ─────────────── roles ─────────────── */
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    /* ─────────────── data model ────────── */
    struct Entry {
        uint32 prefix;       // IPv4, big-endian (e.g. 0xCB007107 for 203.0.113.7)
        uint8  length;       // CIDR 1-32
        uint40 expires;      // Unix epoch seconds; 0 = never
    }

    // Key = prefix<<8 | length
    mapping(uint40 => Entry) private entries;

    /* ─────────────── events ────────────── */
    event BlackholeAdded(
        uint32 indexed prefix,
        uint8  indexed length,
        uint40 expires,
        string reason,
        address indexed operator
    );
    event BlackholeRemoved(
        uint32 indexed prefix,
        uint8  indexed length,
        address indexed operator
    );

    /* ─────────────── constructor ───────── */
    constructor(address firstOperator)
        Ownable(msg.sender)
    {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE,      firstOperator);
    }

    /* ─────────────── public view helpers ─ */
    function getEntry(uint32 prefix, uint8 length)
        external
        view
        returns (Entry memory)
    {
        require(length >= 1 && length <= 32, "bad mask");
        Entry memory e = entries[_key(prefix, length)];
        require(e.length != 0, "not found");
        return e;
    }

    function isBlackholed(uint32 ip)
        external
        view
        returns (bool)
    {
        // Iterate possible masks 32->1 (cheap for single IP queries)
        for (uint8 len = 32; len >= 1; --len) {
            uint32 masked = ip & _mask(len);
            Entry memory e = entries[_key(masked, len)];
            if (e.length == 0) continue;
            if (e.expires != 0 && block.timestamp > e.expires) continue;
            return true;
        }
        return false;
    }

    /* ─────────────── state-changing ops ─── */

    /**
     * @notice Add a blackhole rule.
     * @param prefix   IPv4 address in integer form (big-endian).
     * @param length   CIDR mask bits (1-32).
     * @param ttlSecs  0 = never expire; else seconds from now (max 7 days).
     * @param reason   Short human string (logged in the event).
     */
    function addBlackhole(
        uint32 prefix,
        uint8  length,
        uint32 ttlSecs,
        string calldata reason
    )
        external
        whenNotPaused
        onlyRole(OPERATOR_ROLE)
        nonReentrant
    {
        require(length >= 1 && length <= 32,  "mask 1-32");
        require(ttlSecs <= 7 days,            "TTL > 7d");

        uint32 alignedPrefix = prefix & _mask(length); // ensure network bits only
        uint40 k             = _key(alignedPrefix, length);

        // If exists and still active, reject
        Entry storage existing = entries[k];
        if (existing.length != 0 && (existing.expires == 0 || block.timestamp <= existing.expires)) {
            revert("already active");
        }

        uint40 exp = ttlSecs == 0 ? 0 : uint40(block.timestamp + ttlSecs);
        entries[k] = Entry(alignedPrefix, length, exp);

        emit BlackholeAdded(alignedPrefix, length, exp, reason, msg.sender);
    }

    /**
     * @notice Remove a blackhole before expiry.
     */
    function removeBlackhole(uint32 prefix, uint8 length)
        external
        onlyRole(OPERATOR_ROLE)
        whenNotPaused
        nonReentrant
    {
        uint40 k = _key(prefix & _mask(length), length);
        Entry storage e = entries[k];
        require(e.length != 0, "not found");

        delete entries[k];
        emit BlackholeRemoved(prefix, length, msg.sender);
    }

    /* ─────────────── admin ──────────────── */
    function pause()   external onlyOwner { _pause();  }
    function unpause() external onlyOwner { _unpause();}

    /* ─────────────── internal utils ─────── */
    function _key(uint32 p, uint8 len) private pure returns (uint40) {
        return (uint40(p) << 8) | uint40(len);
    }
    function _mask(uint8 len) private pure returns (uint32) {
        return len == 32 ? type(uint32).max : uint32(type(uint32).max << (32 - len));
    }
}
