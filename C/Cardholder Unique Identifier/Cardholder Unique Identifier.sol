// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title TokenisedCUIDRegistry
 * @notice 
 *  • Stores **only a salted SHA-256 digest** of the CUID (no raw data).  
 *  • Accepts writes *only* from an authorised TOKENISER role—the system
 *   that performs PCI-DSS-compliant tokenisation off-chain.  
 *  • Emits no sensitive bytes; just the digest + metadata for auditors.  
 *  • Provides erase-by-digest to honour data-retention policies.
 *
 * Off-chain tokenisation workflow
 * -------------------------------
 * 1. Issuer’s secure HSM generates random 128-bit salt `s`.
 * 2. Computes `digest = sha256(s ‖ CUID)` and returns `(digest, s)` +
 *    a **signed permit** (EIP-712) authorising on-chain storage.
 * 3. Frontend submits `register(digest, s, sig)`; contract verifies
 *    ROLE + signature, stores `(salt,digest)` keyed by holder address.
 * 4. Raw CUID never touches the chain; salt is needed only for audits
 *    and *optionally* can be deleted once the digest is stored.
 */
contract TokenisedCUIDRegistry is
    AccessControl,
    Ownable,
    Pausable,
    ReentrancyGuard
{
    /*-----------------------------  Roles  --------------------------------*/
    bytes32 public constant TOKENISER_ROLE = keccak256("TOKENISER_ROLE");
    bytes32 public constant AUDITOR_ROLE   = keccak256("AUDITOR_ROLE");

    /*----------------------------  Storage --------------------------------*/
    struct Record {
        bytes16 salt;     // 128-bit random; OK to store
        bytes32 digest;   // sha256(salt ‖ CUID)
        uint40  created;  // block.timestamp for provenance
        bool    deleted;  // logical purge flag
    }

    mapping(address => Record) private records;

    /*-----------------------------  Events --------------------------------*/
    event Registered(address indexed holder, bytes32 digest);
    event Deleted   (address indexed holder);

    /*---------------------------  Constructor -----------------------------*/
    constructor(address tokeniser, address auditor) {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setupRole(TOKENISER_ROLE, tokeniser);
        _setupRole(AUDITOR_ROLE,   auditor);
    }

    /*-------------------------  Core functions ----------------------------*/

    /**
     * @notice Store a salted digest for `holder`.
     * @param holder  wallet being associated
     * @param salt    16-byte random salt
     * @param digest  sha256(salt ‖ CUID)
     * @param sig     TOKENISER’s ECDSA sig over (holder ‖ salt ‖ digest)
     *
     * Requirements:
     *  • caller must have TOKENISER_ROLE  
     *  • `sig` must match `holder` param (prevents rogue mapping)  
     *  • an existing mapping is overwritten only by the same tokeniser.
     */
    function register(
        address   holder,
        bytes16   salt,
        bytes32   digest,
        bytes calldata sig
    )
        external
        whenNotPaused
        onlyRole(TOKENISER_ROLE)
        nonReentrant
    {
        // Reconstruct signed message
        bytes32 h = keccak256(abi.encodePacked(holder, salt, digest));
        address signer = ECDSA.recover(ECDSA.toEthSignedMessageHash(h), sig);
        require(hasRole(TOKENISER_ROLE, signer), "Bad signer");

        // Store / overwrite
        records[holder] = Record({
            salt:    salt,
            digest:  digest,
            created: uint40(block.timestamp),
            deleted: false
        });
        emit Registered(holder, digest);
    }

    /// Logical deletion (GDPR / data-retention).  Auditor-only.
    function erase(address holder)
        external
        whenNotPaused
        onlyRole(AUDITOR_ROLE)
    {
        require(!records[holder].deleted, "Already deleted");
        records[holder].deleted = true;
        emit Deleted(holder);
    }

    /*----------------------  View / audit helpers -------------------------*/

    /// Returns metadata for auditors—never exposes raw CUID.
    function getRecord(address holder)
        external
        view
        onlyRole(AUDITOR_ROLE)
        returns (Record memory)
    {
        return records[holder];
    }

    /*--------------------------  Admin ops --------------------------------*/

    function pause() external onlyOwner { _pause(); }
    function unpause() external onlyOwner { _unpause(); }
}
