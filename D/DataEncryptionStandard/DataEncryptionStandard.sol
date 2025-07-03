// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title DESVerifiedStore
 * @notice
 *   Stores DES (FIPS 46-3) ciphertexts on-chain only after verifying
 *   a short “proof of correct encryption” test vector off-chain.
 *
 * Workflow:
 *   1. Off-chain system holds the DES key and IV.
 *   2. To store data:
 *      a. Off-chain encrypt the 64-bit test block (e.g., all-zero block) under key+IV,
 *         producing a 64-bit test ciphertext `tc`.
 *      b. Off-chain encrypt the real plaintext blocks under key+IV, producing `C[]`.
 *      c. Call `storeCiphertext(recordId, iv, tc, C)` on-chain.
 *   3. On-chain, the contract checks `keccak256(iv, tc, recordId)` matches a pre-registered
 *      “proof” hash for that recordId. If it matches, it accepts the real ciphertext.
 *
 * This version fixes the “Copying nested calldata dynamic arrays to storage is not implemented”
 * error by pushing each block from calldata into storage individually.
 */
contract DESVerifiedStore is AccessControl, Pausable {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    struct Record {
        bytes8   iv;         // 64-bit IV used
        bytes8   testC;      // test-vector ciphertext
        bytes[]  ciphertext; // real data blocks
        bool     exists;
    }

    // recordId ⇒ Record
    mapping(uint256 => Record) private _records;
    // recordId ⇒ expected proof hash
    mapping(uint256 => bytes32) public proofHash;

    event ProofRegistered(uint256 indexed recordId, bytes32 proofHash);
    event CipherStored   (uint256 indexed recordId, bytes8 iv, bytes8 testC, bytes[] ciphertext);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);
    }

    /// @notice Register the expected DES test-vector hash for a record
    function registerProof(uint256 recordId, bytes32 expectedHash)
        external
        onlyRole(ADMIN_ROLE)
    {
        proofHash[recordId] = expectedHash;
        emit ProofRegistered(recordId, expectedHash);
    }

    /**
     * @notice Store DES ciphertext blocks after verifying the test vector.
     * @param recordId   Identifier for this record.
     * @param iv         8-byte IV used in CBC mode.
     * @param testC      8-byte ciphertext of the known test block.
     * @param ciphertext Array of 8-byte ciphertext blocks for real data.
     */
    function storeCiphertext(
        uint256 recordId,
        bytes8 iv,
        bytes8 testC,
        bytes[] calldata ciphertext
    )
        external
        whenNotPaused
    {
        require(proofHash[recordId] != 0, "Proof not registered");
        // On-chain check: hash(iv, testC, recordId) must match the registered proof
        bytes32 h = keccak256(abi.encodePacked(iv, testC, recordId));
        require(h == proofHash[recordId], "Test-vector proof mismatch");

        Record storage r = _records[recordId];
        require(!r.exists, "Already stored");

        // Copy nested calldata array into storage manually
        for (uint256 i = 0; i < ciphertext.length; i++) {
            r.ciphertext.push(ciphertext[i]);
        }

        r.iv     = iv;
        r.testC  = testC;
        r.exists = true;

        emit CipherStored(recordId, iv, testC, r.ciphertext);
    }

    /// @notice Retrieve stored ciphertext blocks
    function getCiphertext(uint256 recordId)
        external
        view
        returns (bytes8 iv, bytes8 testC, bytes[] memory ciphertext)
    {
        Record storage r = _records[recordId];
        require(r.exists, "Not stored");
        return (r.iv, r.testC, r.ciphertext);
    }

    /// @notice Pause operations in emergencies
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause operations
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
