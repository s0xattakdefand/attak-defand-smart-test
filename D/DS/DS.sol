// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/* ── OpenZeppelin v5 ──────────────────────────────────────────────── */
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/* ───────────────────────────────────────────────────────────────────
 *                       DirectoryService
 * ───────────────────────────────────────────────────────────────────
 *  ▸ Identity entries  – subjects (people / machines) keyed by a 32-byte ID
 *  ▸ Certificate store – SHA-256 fingerprint → metadata
 *  ▸ CRL status        – on-chain revocation with reason + timestamp
 *
 *  Gas-efficient: only hashes are stored, raw X.509 goes off-chain/IPFS.
 */
contract DirectoryService is
    AccessControl,
    Pausable,
    ReentrancyGuard,
    Ownable
{
    /* ───────────── Roles ───────────── */
    bytes32 public constant ISSUER_ROLE = keccak256("ISSUER_ROLE"); // CAs / RAs

    /* ───────────── Data structures ─── */

    struct Identity {
        bytes32  id;          // canonical 32-byte ID (e.g., subjectKeyId hash)
        string   display;     // human-readable name
        address  wallet;      // optional on-chain address
        uint64   created;     // unix epoch
    }

    struct Certificate {
        bytes32  fingerprint; // SHA-256 of DER
        bytes32  subjectId;   // → Identity.id
        bytes32  issuerId;    // issuing CA identity
        uint64   validFrom;   // epoch
        uint64   validTo;     // epoch
        bool     revoked;     // CRL flag
        uint64   revokedAt;   // epoch (0 if not revoked)
        string   revReason;   // short text
    }

    /* ───────────── Storage ─────────── */
    mapping(bytes32 => Identity)    private _identities;   // id → Identity
    mapping(bytes32 => Certificate) private _certs;        // fingerprint → Cert

    /* ───────────── Events ──────────── */
    event IdentityRegistered(bytes32 indexed id, string display, address wallet);
    event CertPublished(
        bytes32 indexed fingerprint,
        bytes32 indexed subjectId,
        bytes32 indexed issuerId,
        uint64  validFrom,
        uint64  validTo
    );
    event CertRevoked(
        bytes32 indexed fingerprint,
        string  reason,
        uint64  revokedAt
    );

    /* ───────────── Constructor ─────── */
    constructor(address initialIssuer) Ownable(msg.sender) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ISSUER_ROLE,        initialIssuer);
    }

    /* ───────────── Identity API ────── */

    function registerIdentity(
        bytes32 id,
        string  calldata display,
        address wallet
    )
        external
        onlyRole(ISSUER_ROLE)
        whenNotPaused
        nonReentrant
    {
        require(_identities[id].created == 0, "id exists");
        _identities[id] = Identity({
            id:      id,
            display: display,
            wallet:  wallet,
            created: uint64(block.timestamp)
        });
        emit IdentityRegistered(id, display, wallet);
    }

    function getIdentity(bytes32 id)
        external
        view
        returns (Identity memory)
    {
        Identity memory i = _identities[id];
        require(i.created != 0, "not found");
        return i;
    }

    /* ───────────── Certificate API ─── */

    function publishCert(
        bytes32 fingerprint,
        bytes32 subjectId,
        bytes32 issuerId,
        uint64  validFrom,
        uint64  validTo
    )
        external
        onlyRole(ISSUER_ROLE)
        whenNotPaused
        nonReentrant
    {
        require(_certs[fingerprint].validTo == 0, "cert exists");
        require(_identities[subjectId].created != 0, "unknown subject");
        require(_identities[issuerId].created  != 0, "unknown issuer");
        require(validTo > validFrom, "bad validity");

        _certs[fingerprint] = Certificate({
            fingerprint: fingerprint,
            subjectId:   subjectId,
            issuerId:    issuerId,
            validFrom:   validFrom,
            validTo:     validTo,
            revoked:     false,
            revokedAt:   0,
            revReason:   ""
        });

        emit CertPublished(fingerprint, subjectId, issuerId, validFrom, validTo);
    }

    function revokeCert(bytes32 fingerprint, string calldata reason)
        external
        onlyRole(ISSUER_ROLE)
        whenNotPaused
        nonReentrant
    {
        Certificate storage c = _certs[fingerprint];
        require(c.validTo != 0, "cert unknown");
        require(!c.revoked,     "already revoked");

        c.revoked   = true;
        c.revokedAt = uint64(block.timestamp);
        c.revReason = reason;

        emit CertRevoked(fingerprint, reason, c.revokedAt);
    }

    /* ───────────── Query helpers ───── */

    function getCert(bytes32 fp)
        external
        view
        returns (Certificate memory)
    {
        Certificate memory c = _certs[fp];
        require(c.validTo != 0, "not found");
        return c;
    }

    /// @notice Returns true iff certificate is present, within validity,
    ///         and NOT revoked at current block time.
    function isCertValid(bytes32 fp) external view returns (bool) {
        Certificate memory c = _certs[fp];
        if (c.validTo == 0)                return false; // unknown
        if (c.revoked)                     return false; // CRL hit
        if (block.timestamp < c.validFrom) return false; // not yet valid
        if (block.timestamp > c.validTo)   return false; // expired
        return true;
    }

    /* ───────────── Admin / ops ─────── */
    function pause()   external onlyOwner { _pause(); }
    function unpause() external onlyOwner { _unpause(); }
}
