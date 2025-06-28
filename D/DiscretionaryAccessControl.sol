// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/* ── OpenZeppelin v5 ─────────────────────────────────────────────── */
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/* ───────────────────────────────────────────────────────────────────
 *                    DiscretionaryAccessControl
 *
 *  • DAC = owner of each object (resource) decides who else can access.
 *  • Resource key = bytes32  (could be file hash, URI hash, UUID…)
 *  • Permission bits:
 *         READ    = 0x01
 *         WRITE   = 0x02
 *         EXECUTE = 0x04
 *  • Owner can grant / revoke any subset to any principal (address).
 *  • Public view functions let dApps enforce access client-side.
 */
contract DiscretionaryAccessControl is
    Ownable,
    Pausable,
    ReentrancyGuard
{
    /* ───── permission constants ───── */
    uint8 public constant PERM_READ    = 0x01;
    uint8 public constant PERM_WRITE   = 0x02;
    uint8 public constant PERM_EXECUTE = 0x04;

    /* ───── resource metadata ──────── */
    struct Resource {
        address owner;     // creator / controlling subject
        uint64  created;   // epoch
    }

    /* ───── storage ───────────────── */
    mapping(bytes32 => Resource)                private _resources; // key → meta
    mapping(bytes32 => mapping(address => uint8)) private _acl;      // key → (subject→perm bits)

    /* ───── events ────────────────── */
    event ResourceRegistered(bytes32 indexed key, address indexed owner);
    event PermissionGranted (bytes32 indexed key, address indexed subject, uint8 perms);
    event PermissionRevoked (bytes32 indexed key, address indexed subject, uint8 perms);
    event ResourceOwnershipTransferred(bytes32 indexed key, address oldOwner, address newOwner);

    /* ───── constructor ───────────── */
    constructor() Ownable(msg.sender) {}

    /* ───── resource API ───────────── */

    /**
     * @notice Register a new resource; caller becomes its owner.
     * @param key  Unique identifier (must not exist).
     */
    function registerResource(bytes32 key)
        external
        whenNotPaused
        nonReentrant
    {
        require(_resources[key].owner == address(0), "resource exists");
        _resources[key] = Resource(msg.sender, uint64(block.timestamp));

        // By default owner gets full permissions (R|W|X)
        _acl[key][msg.sender] = PERM_READ | PERM_WRITE | PERM_EXECUTE;

        emit ResourceRegistered(key, msg.sender);
    }

    /**
     * @notice Transfer resource ownership.
     */
    function transferResource(bytes32 key, address newOwner)
        external
        whenNotPaused
        nonReentrant
    {
        require(_resources[key].owner == msg.sender, "not owner");
        require(newOwner != address(0), "zero owner");

        address old = _resources[key].owner;
        _resources[key].owner = newOwner;

        // Optional: grant full permissions to new owner
        _acl[key][newOwner] |= (PERM_READ | PERM_WRITE | PERM_EXECUTE);

        emit ResourceOwnershipTransferred(key, old, newOwner);
    }

    /* ───── DAC: grant / revoke ────── */

    /**
     * @notice Grant `perms` to `subject` on `key`.
     */
    function grantPerms(
        bytes32 key,
        address subject,
        uint8   perms
    )
        external
        whenNotPaused
        nonReentrant
    {
        require(_resources[key].owner == msg.sender, "not owner");
        require(perms > 0, "no perms");
        _acl[key][subject] |= perms;
        emit PermissionGranted(key, subject, perms);
    }

    /**
     * @notice Revoke specific permission bits.
     */
    function revokePerms(
        bytes32 key,
        address subject,
        uint8   perms
    )
        external
        whenNotPaused
        nonReentrant
    {
        require(_resources[key].owner == msg.sender, "not owner");
        require(perms > 0, "no perms");
        _acl[key][subject] &= ~perms;
        emit PermissionRevoked(key, subject, perms);
    }

    /* ───── view helpers ───────────── */

    function hasPerm(
        bytes32 key,
        address subject,
        uint8   perm
    )
        external
        view
        returns (bool)
    {
        return (_acl[key][subject] & perm) != 0;
    }

    function getPermBits(bytes32 key, address subject)
        external
        view
        returns (uint8)
    {
        return _acl[key][subject];
    }

    function getResource(bytes32 key)
        external
        view
        returns (Resource memory)
    {
        Resource memory r = _resources[key];
        require(r.owner != address(0), "unknown");
        return r;
    }

    /* ───── emergency ─────────────── */
    function pause()   external onlyOwner { _pause(); }
    function unpause() external onlyOwner { _unpause(); }
}
