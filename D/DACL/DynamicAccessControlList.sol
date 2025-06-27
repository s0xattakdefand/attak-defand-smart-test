// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/* ── OpenZeppelin (v5) ─────────────────────────────────────────── */
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/* ────────────────────────────────────────────────────────────────
 *                    DiscretionaryACL
 *
 *  • Any user can register a resource (bytes32 key).
 *  • The resource *owner* can grant / revoke permission bits to others:
 *        READ    = 0x01
 *        WRITE   = 0x02
 *        EXECUTE = 0x04
 *  • Everyone can query who has what.
 *  • Contract owner can pause the whole registry if needed.
 */
contract DiscretionaryACL is
    Ownable,
    Pausable,
    ReentrancyGuard
{
    /* ------------- permission constants ------------- */
    uint8 public constant PERM_READ    = 0x01;
    uint8 public constant PERM_WRITE   = 0x02;
    uint8 public constant PERM_EXECUTE = 0x04;

    /* ------------- data structures ------------------ */
    struct Resource {
        address owner;
        uint64  created;
    }

    mapping(bytes32 => Resource)                 private _resources; // key → meta
    mapping(bytes32 => mapping(address => uint8)) private _acl;      // key → (subject → bits)

    /* ------------- events --------------------------- */
    event ResourceRegistered(bytes32 indexed key, address indexed owner);
    event PermissionGranted (bytes32 indexed key, address indexed subject, uint8 bits);
    event PermissionRevoked (bytes32 indexed key, address indexed subject, uint8 bits);
    event OwnerTransferred  (bytes32 indexed key, address oldOwner, address newOwner);

    /* ------------- constructor ---------------------- */
    constructor() Ownable(msg.sender) {}

    /* ------------- resource API --------------------- */

    function registerResource(bytes32 key)
        external
        whenNotPaused
    {
        require(_resources[key].owner == address(0), "resource exists");
        _resources[key] = Resource(msg.sender, uint64(block.timestamp));

        // Give full rights to creator
        _acl[key][msg.sender] =
            PERM_READ | PERM_WRITE | PERM_EXECUTE;

        emit ResourceRegistered(key, msg.sender);
    }

    function transferResource(bytes32 key, address newOwner)
        external
        whenNotPaused
    {
        require(_resources[key].owner == msg.sender, "not owner");
        require(newOwner != address(0), "zero owner");

        address old = _resources[key].owner;
        _resources[key].owner = newOwner;

        // Ensure new owner has full rights
        _acl[key][newOwner] |= PERM_READ | PERM_WRITE | PERM_EXECUTE;

        emit OwnerTransferred(key, old, newOwner);
    }

    /* ------------- grant / revoke ------------------- */

    function grantPerms(
        bytes32 key,
        address subject,
        uint8   bits
    )
        external
        whenNotPaused
    {
        require(_resources[key].owner == msg.sender, "not owner");
        require(bits != 0, "no bits");
        _acl[key][subject] |= bits;
        emit PermissionGranted(key, subject, bits);
    }

    function revokePerms(
        bytes32 key,
        address subject,
        uint8   bits
    )
        external
        whenNotPaused
    {
        require(_resources[key].owner == msg.sender, "not owner");
        require(bits != 0, "no bits");
        _acl[key][subject] &= ~bits;
        emit PermissionRevoked(key, subject, bits);
    }

    /* ------------- view helpers --------------------- */

    function hasPerm(bytes32 key, address subject, uint8 bit)
        external
        view
        returns (bool)
    {
        return (_acl[key][subject] & bit) != 0;
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
        Resource memory res = _resources[key];
        require(res.owner != address(0), "unknown resource");
        return res;
    }

    /* ------------- pause controls ------------------- */
    function pause()   external onlyOwner { _pause(); }
    function unpause() external onlyOwner { _unpause(); }
}
