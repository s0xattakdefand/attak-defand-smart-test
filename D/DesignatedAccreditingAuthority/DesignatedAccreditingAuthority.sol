// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/* ── OpenZeppelin v5 ─────────────────────────────────────────────── */
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/* ───────────────────────────────────────────────────────────────────
 *                        DesignatedAccreditingAuthorityRegistry
 *
 *  ▸ OWNER (e.g., Agency CISO) manages the roster of DAAs.
 *  ▸ A DAA may  accreditSystem(), updateATO(), or revokeATO()
 *  ▸ Anyone can  getATO() to verify current authorisation status.
 *
 *  STATUS enum mirrors RMF language:  AUTHORISED | DENIED | REVOKED.
 *  Each ATO carries an expiry (“Authorization Termination Date”).
 */
contract DesignatedAccreditingAuthorityRegistry is
    Ownable,          // needs initial owner arg
    AccessControl,
    Pausable,
    ReentrancyGuard
{
    /* ─────────── roles ─────────── */
    bytes32 public constant DAA_ROLE = keccak256("DAA_ROLE");

    /* ─────────── data model ────── */
    enum Status { NONE, AUTHORISED, DENIED, REVOKED }

    struct ATO {
        string   systemId;     // unique system name or UUID
        address  daa;          // signing DAA
        Status   status;
        uint64   issued;       // epoch
        uint64   expires;      // 0 = no expiry
        string   memo;         // free text (e.g., POAM summary)
    }

    mapping(string => ATO) private _atos;   // systemId → ATO

    /* ─────────── events ────────── */
    event DAAAdded   (address indexed daa);
    event DAARemoved (address indexed daa);
    event ATOIssued  (string indexed systemId, address indexed daa, Status s, uint64 expires, string memo);
    event ATORevoked (string indexed systemId, address indexed daa, string reason);

    /* ─────────── constructor ───── */
    constructor(address firstDAA) Ownable(msg.sender) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(DAA_ROLE,           firstDAA);
    }

    /* ─────────── DAA roster ops ── */
    function addDAA(address newDaa) external onlyOwner {
        _grantRole(DAA_ROLE, newDaa);
        emit DAAAdded(newDaa);
    }
    function removeDAA(address daa) external onlyOwner {
        _revokeRole(DAA_ROLE, daa);
        emit DAARemoved(daa);
    }

    /* ─────────── ATO ops ───────── */

    /**
     * @notice Issue or renew an ATO for `systemId`.
     * @param systemId Unique system identifier (string).
     * @param approve  true = AUTHORISED, false = DENIED.
     * @param ttlSecs  0 for no expiry; else expires = now + ttl.
     * @param memo     Free text (stored on-chain).
     */
    function accreditSystem(
        string calldata systemId,
        bool   approve,
        uint32 ttlSecs,
        string calldata memo
    )
        external
        onlyRole(DAA_ROLE)
        whenNotPaused
        nonReentrant
    {
        require(bytes(systemId).length > 0, "blank id");
        require(ttlSecs <= 365 days,        "ttl > 1yr");

        Status newStatus = approve ? Status.AUTHORISED : Status.DENIED;
        uint64 exp       = ttlSecs == 0 ? 0 : uint64(block.timestamp) + ttlSecs;

        _atos[systemId] = ATO({
            systemId: systemId,
            daa:      msg.sender,
            status:   newStatus,
            issued:   uint64(block.timestamp),
            expires:  exp,
            memo:     memo
        });

        emit ATOIssued(systemId, msg.sender, newStatus, exp, memo);
    }

    /**
     * @notice Revoke an existing ATO.
     */
    function revokeATO(string calldata systemId, string calldata reason)
        external
        onlyRole(DAA_ROLE)
        whenNotPaused
        nonReentrant
    {
        ATO storage a = _atos[systemId];
        require(a.status == Status.AUTHORISED, "not authorised");
        a.status  = Status.REVOKED;
        a.expires = uint64(block.timestamp);
        a.memo    = reason;
        emit ATORevoked(systemId, msg.sender, reason);
    }

    /* ─────────── views ─────────── */

    function getATO(string calldata systemId)
        external
        view
        returns (ATO memory)
    {
        ATO memory a = _atos[systemId];
        require(a.status != Status.NONE, "unknown system");
        return a;
    }

    function isSystemAuthorised(string calldata systemId)
        external
        view
        returns (bool)
    {
        ATO memory a = _atos[systemId];
        if (a.status != Status.AUTHORISED)         return false;
        if (a.expires != 0 && block.timestamp > a.expires) return false;
        return true;
    }

    /* ─────────── admin ─────────── */
    function pause()   external onlyOwner { _pause(); }
    function unpause() external onlyOwner { _unpause(); }
}
