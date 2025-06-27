// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/*═══════════════════════════════════════════════════════════════*\
 ░░  NIST SP 800-160 Vol. 2 Rev. 1 – Cyber-Resilience NFT        ░░
\*═══════════════════════════════════════════════════════════════*/

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

contract NIST800160V2R1 is ERC721URIStorage, AccessControl, Pausable {
    /*────────────────────── ROLES ──────────────────────*/
    bytes32 public constant AUDITOR_ROLE = keccak256("AUDITOR_ROLE");

    /*───────────────────── EVENTS ──────────────────────*/
    event CertificateIssued   (address indexed org, uint256 indexed certId, string uri);
    event CertificateRevoked  (uint256 indexed certId);
    event CertificateUpdated  (uint256 indexed certId, string newUri);

    /*──────────────────── STORAGE ─────────────────────*/
    uint256 private _nextId = 1;

    /*─────────────── CONSTRUCTOR ──────────────────────*/
    constructor(address superAdmin)
        ERC721("NIST SP 800-160 V2R1 Certificate", "NIST-CRS")
    {
        _grantRole(DEFAULT_ADMIN_ROLE, superAdmin);
    }

    /*─────────────────── MODIFIERS ────────────────────*/
    modifier onlyAuditor() { _checkRole(AUDITOR_ROLE); _; }

    /*──────────────────── ACTIONS ─────────────────────*/

    function issueCertificate(address org, string calldata uri)
        external
        whenNotPaused
        onlyAuditor
        returns (uint256 certId)
    {
        certId = _nextId++;
        _safeMint(org, certId);
        _setTokenURI(certId, uri);
        emit CertificateIssued(org, certId, uri);
    }

    function updateCertificateURI(uint256 certId, string calldata newUri)
        external
        whenNotPaused
    {
        // ── OpenZeppelin v5 helper replaces _isApprovedOrOwner ──
        require(
            _isAuthorized(msg.sender, certId) || hasRole(AUDITOR_ROLE, msg.sender),
            "NIST-CRS: not authorized"
        );
        _setTokenURI(certId, newUri);
        emit CertificateUpdated(certId, newUri);
    }

    function revokeCertificate(uint256 certId)
        external
        whenNotPaused
        onlyAuditor
    {
        _burn(certId);
        emit CertificateRevoked(certId);
    }

    /*───────────────── ADMIN CONTROLS ─────────────────*/
    function pause()  external onlyRole(DEFAULT_ADMIN_ROLE) { _pause();  }
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) { _unpause(); }

    /*───────────── NON-TRANSFERABLE (soul-bound) ───────*/
    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 id,
        uint256
    )
        internal
        override
        whenNotPaused
    {
        // Disallow transfers unless the admin performs them.
        if (from != address(0) && !hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            revert("NIST-CRS: non-transferable");
        }
        super._beforeTokenTransfer(from, to, id, 0);
    }

    /*──────────── COLLECTION-LEVEL METADATA ────────────*/
    function contractURI() external pure returns (string memory) {
        // Replace CID with your actual collection metadata file.
        return "ipfs://Qm1234567890abcdef1234567890abcdef12345678/NIST800-160V2R1.json";
    }
}
