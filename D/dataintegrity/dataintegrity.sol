// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title DataIntegrityManager
 * @notice
 *   Ensures data integrity across storage, processing, and transit per CNSSI 4009-2015:
 *   • ADMIN_ROLE manages roles and can pause/unpause.
 *   • WRITER_ROLE may register and update stored data hashes (data at rest).
 *   • TRANSPORT_ROLE may log data-in-transit hashes.
 *   • PROCESSOR_ROLE may log processing steps and output hashes.
 *
 * Data Model:
 *   • Each data asset has an ID, description, and a storedHash representing its integrity at rest.
 *   • Transit logs record the hash of the asset while moving.
 *   • Processing logs record input and output hashes for transformations.
 *
 * Integrity checks can be performed off-chain by comparing these hashes.
 */
contract DataIntegrityManager is AccessControl, Pausable {
    bytes32 public constant WRITER_ROLE    = keccak256("WRITER_ROLE");
    bytes32 public constant TRANSPORT_ROLE = keccak256("TRANSPORT_ROLE");
    bytes32 public constant PROCESSOR_ROLE = keccak256("PROCESSOR_ROLE");

    struct Asset {
        string   description;
        bytes32  storedHash;
        bool     exists;
    }

    // assetId ⇒ Asset
    mapping(uint256 => Asset) private _assets;

    // Transit and processing logs
    event AssetRegistered(uint256 indexed assetId, string description, bytes32 storedHash);
    event AssetUpdated   (uint256 indexed assetId, bytes32 newStoredHash);
    event TransitLogged  (uint256 indexed assetId, bytes32 transitHash, address indexed by, uint256 timestamp);
    event ProcessingLogged(
        uint256 indexed assetId,
        bytes32 inputHash,
        bytes32 outputHash,
        address indexed by,
        uint256 timestamp
    );

    modifier onlyAdmin() {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "DIM: not admin");
        _;
    }
    modifier onlyWriter() {
        require(hasRole(WRITER_ROLE, msg.sender), "DIM: not writer");
        _;
    }
    modifier onlyTransport() {
        require(hasRole(TRANSPORT_ROLE, msg.sender), "DIM: not transport");
        _;
    }
    modifier onlyProcessor() {
        require(hasRole(PROCESSOR_ROLE, msg.sender), "DIM: not processor");
        _;
    }

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(WRITER_ROLE, admin);
        _grantRole(TRANSPORT_ROLE, admin);
        _grantRole(PROCESSOR_ROLE, admin);
    }

    /// @notice Pause all integrity operations
    function pause() external onlyAdmin {
        _pause();
    }

    /// @notice Unpause integrity operations
    function unpause() external onlyAdmin {
        _unpause();
    }

    /// @notice Register a new data asset with its integrity hash at rest
    function registerAsset(
        uint256 assetId,
        string calldata description,
        bytes32 storedHash
    )
        external
        whenNotPaused
        onlyWriter
    {
        require(!_assets[assetId].exists, "DIM: asset exists");
        _assets[assetId] = Asset({
            description: description,
            storedHash:  storedHash,
            exists:      true
        });
        emit AssetRegistered(assetId, description, storedHash);
    }

    /// @notice Update the storedHash of an existing asset (e.g. after legitimate change)
    function updateAssetHash(uint256 assetId, bytes32 newStoredHash)
        external
        whenNotPaused
        onlyWriter
    {
        Asset storage a = _assets[assetId];
        require(a.exists, "DIM: asset not found");
        a.storedHash = newStoredHash;
        emit AssetUpdated(assetId, newStoredHash);
    }

    /// @notice Log the hash of an asset while in transit
    function logTransit(uint256 assetId, bytes32 transitHash)
        external
        whenNotPaused
        onlyTransport
    {
        require(_assets[assetId].exists, "DIM: asset not found");
        emit TransitLogged(assetId, transitHash, msg.sender, block.timestamp);
    }

    /// @notice Log a processing step: input → output hash
    function logProcessing(
        uint256 assetId,
        bytes32 inputHash,
        bytes32 outputHash
    )
        external
        whenNotPaused
        onlyProcessor
    {
        require(_assets[assetId].exists, "DIM: asset not found");
        emit ProcessingLogged(assetId, inputHash, outputHash, msg.sender, block.timestamp);
    }

    /// @notice Retrieve an asset’s description and stored hash
    function getAsset(uint256 assetId)
        external
        view
        returns (string memory description, bytes32 storedHash)
    {
        Asset storage a = _assets[assetId];
        require(a.exists, "DIM: asset not found");
        return (a.description, a.storedHash);
    }
}
