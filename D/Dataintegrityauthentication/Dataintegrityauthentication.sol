// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title IntegrityVerification
 * @notice
 *   Implements the process of determining data integrity (integrity authentication/verification)
 *   per NIST SP 800-175B Rev. 1:
 *   • ADMIN_ROLE registers data items with their expected hash.
 *   • VERIFIER_ROLE can submit raw data to verify against the stored hash.
 *   • Emits events for registration and verification results.
 */
contract IntegrityVerification is AccessControl, Pausable {
    bytes32 public constant ADMIN_ROLE    = keccak256("ADMIN_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    struct DataItem {
        bytes32 expectedHash;  // keccak256 hash of the “true” data
        string  metadataURI;   // optional off-chain pointer or description
        bool    exists;
    }

    // itemId ⇒ DataItem
    mapping(uint256 => DataItem) private _items;

    event DataRegistered(uint256 indexed itemId, bytes32 expectedHash, string metadataURI);
    event VerificationPerformed(
        uint256 indexed itemId,
        address indexed verifier,
        bool    success,
        bytes32 providedHash,
        uint256 timestamp
    );

    modifier onlyAdmin() {
        require(hasRole(ADMIN_ROLE, msg.sender), "IV: not admin");
        _;
    }
    modifier onlyVerifier() {
        require(hasRole(VERIFIER_ROLE, msg.sender), "IV: not verifier");
        _;
    }

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);
    }

    /// @notice Grant VERIFIER_ROLE to an account
    function addVerifier(address acct) external onlyRole(ADMIN_ROLE) {
        grantRole(VERIFIER_ROLE, acct);
    }

    /// @notice Revoke VERIFIER_ROLE from an account
    function removeVerifier(address acct) external onlyRole(ADMIN_ROLE) {
        revokeRole(VERIFIER_ROLE, acct);
    }

    /// @notice Pause all operations
    function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause all operations
    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }

    /**
     * @notice Register a new data item with its expected integrity hash.
     * @param itemId       Unique identifier for the data item.
     * @param expectedHash keccak256 hash of the genuine data.
     * @param metadataURI  Optional pointer or description (e.g. IPFS, URL).
     */
    function registerData(
        uint256 itemId,
        bytes32 expectedHash,
        string calldata metadataURI
    )
        external
        whenNotPaused
        onlyAdmin
    {
        require(!_items[itemId].exists, "IV: item exists");
        _items[itemId] = DataItem({
            expectedHash: expectedHash,
            metadataURI:  metadataURI,
            exists:       true
        });
        emit DataRegistered(itemId, expectedHash, metadataURI);
    }

    /**
     * @notice Update the expected hash for an existing data item.
     * @param itemId       Identifier of the data item.
     * @param expectedHash New expected keccak256 hash.
     */
    function updateExpectedHash(uint256 itemId, bytes32 expectedHash)
        external
        whenNotPaused
        onlyAdmin
    {
        DataItem storage di = _items[itemId];
        require(di.exists, "IV: item not found");
        di.expectedHash = expectedHash;
        emit DataRegistered(itemId, expectedHash, di.metadataURI);
    }

    /**
     * @notice Verify raw data against the registered expected hash.
     * @param itemId Identifier of the data item to verify.
     * @param data   Raw data bytes.
     * @return success True if keccak256(data) matches expected hash.
     */
    function verifyData(uint256 itemId, bytes calldata data)
        external
        whenNotPaused
        onlyVerifier
        returns (bool success)
    {
        DataItem storage di = _items[itemId];
        require(di.exists, "IV: item not found");
        bytes32 providedHash = keccak256(data);
        success = (providedHash == di.expectedHash);
        emit VerificationPerformed(itemId, msg.sender, success, providedHash, block.timestamp);
    }

    /**
     * @notice Retrieve stored metadata for a data item.
     * @param itemId Identifier of the data item.
     * @return expectedHash Registered expected hash.
     * @return metadataURI  Registered metadata URI.
     */
    function getDataItem(uint256 itemId)
        external
        view
        returns (bytes32 expectedHash, string memory metadataURI)
    {
        DataItem storage di = _items[itemId];
        require(di.exists, "IV: item not found");
        return (di.expectedHash, di.metadataURI);
    }
}
