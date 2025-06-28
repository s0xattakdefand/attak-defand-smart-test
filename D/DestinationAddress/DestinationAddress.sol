// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/* ── OpenZeppelin v5 imports ─────────────────────────────────────── */
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/* ───────────────────────────────────────────────────────────────────
 *                     DestinationAddressRegistry
 * ------------------------------------------------------------------
 * Each wallet may store one free-form “destination address” string
 * (shipping address, endpoint URL/IP, etc.).  Users can update or
 * clear their own entry; anyone can read; the contract owner can
 * pause the registry or force-delete abusive content.
 */
contract DestinationAddressRegistry is
    Ownable,          // needs initialOwner in OZ v5
    Pausable,
    ReentrancyGuard
{
    /* ───── constructor ───── */
    constructor() Ownable(msg.sender) {}   // ✔️ supply required argument

    /* ───── storage ───── */
    mapping(address => string) private _dest;

    /* ───── events ───── */
    event DestinationSet    (address indexed user, string value);
    event DestinationCleared(address indexed user);
    event DestinationDeleted(address indexed target, string oldValue);

    /* ───── public API ─── */

    function setDestination(string calldata value)
        external
        whenNotPaused
        nonReentrant
    {
        _dest[msg.sender] = value;
        emit DestinationSet(msg.sender, value);
    }

    function clearDestination()
        external
        whenNotPaused
        nonReentrant
    {
        delete _dest[msg.sender];
        emit DestinationCleared(msg.sender);
    }

    function getDestination(address user)
        external
        view
        returns (string memory)
    {
        return _dest[user];
    }

    /* ───── admin / moderation ─── */

    function forceDelete(address target)
        external
        onlyOwner
        whenNotPaused
    {
        string memory oldVal = _dest[target];
        delete _dest[target];
        emit DestinationDeleted(target, oldVal);
    }

    function pause()   external onlyOwner { _pause();  }
    function unpause() external onlyOwner { _unpause(); }
}
