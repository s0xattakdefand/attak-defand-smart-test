// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title DifferentialPrivacyDataCurator
 * @notice
 *   Implements the “data curator” role from the NIST SP 800-226 trust model:  
 *   • DataProviders submit raw data pointers (off-chain storage).  
 *   • A DataCurator aggregates those submissions into datasets.  
 *   • The Curator then publishes differentially private aggregates for DataConsumers.
 *
 * Roles:
 *   • DEFAULT_ADMIN_ROLE: can pause/unpause, add/remove providers and curators.  
 *   • PROVIDER_ROLE: may submit raw data pointers to a given dataset.  
 *   • CURATOR_ROLE: may aggregate datasets and publish DP‐protected results.
 */
contract DifferentialPrivacyDataCurator is AccessControl, Pausable {
    bytes32 public constant PROVIDER_ROLE = keccak256("PROVIDER_ROLE");
    bytes32 public constant CURATOR_ROLE  = keccak256("CURATOR_ROLE");

    struct RawRecord {
        address provider;
        string  pointer;   // e.g. IPFS hash or URL of raw data
    }

    struct Aggregate {
        address curator;
        string  dpPointer; // off-chain pointer to DP‐protected aggregate
        uint256 timestamp;
    }

    // datasetId ⇒ list of raw records
    mapping(uint256 => RawRecord[]) private _rawData;
    // datasetId ⇒ list of published aggregates (one per version)
    mapping(uint256 => Aggregate[]) private _aggregates;

    event ProviderAdded(address indexed account);
    event ProviderRemoved(address indexed account);
    event CuratorAdded(address indexed account);
    event CuratorRemoved(address indexed account);

    event RawDataSubmitted(
        uint256 indexed datasetId,
        address indexed provider,
        string pointer
    );
    event AggregatePublished(
        uint256 indexed datasetId,
        uint256 indexed version,
        address indexed curator,
        string dpPointer,
        uint256 timestamp
    );

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    modifier onlyProvider() {
        require(hasRole(PROVIDER_ROLE, msg.sender), "Not a data provider");
        _;
    }

    modifier onlyCurator() {
        require(hasRole(CURATOR_ROLE, msg.sender), "Not a data curator");
        _;
    }

    /// @notice Add a new DataProvider
    function addProvider(address acct) external onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(PROVIDER_ROLE, acct);
        emit ProviderAdded(acct);
    }

    /// @notice Remove a DataProvider
    function removeProvider(address acct) external onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(PROVIDER_ROLE, acct);
        emit ProviderRemoved(acct);
    }

    /// @notice Add a new DataCurator
    function addCurator(address acct) external onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(CURATOR_ROLE, acct);
        emit CuratorAdded(acct);
    }

    /// @notice Remove a DataCurator
    function removeCurator(address acct) external onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(CURATOR_ROLE, acct);
        emit CuratorRemoved(acct);
    }

    /// @notice Pause all operations
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause all operations
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /**
     * @notice Providers submit raw data pointers into a dataset.
     * @param datasetId Identifier for the dataset
     * @param pointer Off-chain location of the raw data (e.g. IPFS hash)
     */
    function submitRawData(uint256 datasetId, string calldata pointer)
        external
        whenNotPaused
        onlyProvider
    {
        require(bytes(pointer).length > 0, "Pointer required");
        _rawData[datasetId].push(RawRecord({
            provider: msg.sender,
            pointer:  pointer
        }));
        emit RawDataSubmitted(datasetId, msg.sender, pointer);
    }

    /**
     * @notice Curator publishes a differentially private aggregate for a dataset.
     * @param datasetId Identifier for the dataset
     * @param dpPointer Off-chain location of the DP-protected aggregate
     */
    function publishAggregate(uint256 datasetId, string calldata dpPointer)
        external
        whenNotPaused
        onlyCurator
    {
        require(bytes(dpPointer).length > 0, "Pointer required");
        uint256 version = _aggregates[datasetId].length;
        _aggregates[datasetId].push(Aggregate({
            curator:   msg.sender,
            dpPointer: dpPointer,
            timestamp: block.timestamp
        }));
        emit AggregatePublished(datasetId, version, msg.sender, dpPointer, block.timestamp);
    }

    /**
     * @notice Retrieve all raw data pointers for a given dataset.
     * @param datasetId Identifier for the dataset
     * @return providers List of provider addresses
     * @return pointers List of raw‐data pointers
     */
    function getRawData(uint256 datasetId)
        external
        view
        returns (address[] memory providers, string[] memory pointers)
    {
        RawRecord[] storage recs = _rawData[datasetId];
        uint256 n = recs.length;
        providers = new address[](n);
        pointers  = new string[](n);
        for (uint256 i = 0; i < n; i++) {
            providers[i] = recs[i].provider;
            pointers[i]  = recs[i].pointer;
        }
    }

    /**
     * @notice Retrieve all published DP aggregates for a dataset.
     * @param datasetId Identifier for the dataset
     * @return curators List of curator addresses
     * @return dpPointers List of DP‐aggregate pointers
     * @return timestamps List of publication timestamps
     */
    function getAggregates(uint256 datasetId)
        external
        view
        returns (
            address[] memory curators,
            string[]  memory dpPointers,
            uint256[] memory timestamps
        )
    {
        Aggregate[] storage aggs = _aggregates[datasetId];
        uint256 m = aggs.length;
        curators   = new address[](m);
        dpPointers = new string[](m);
        timestamps = new uint256[](m);
        for (uint256 i = 0; i < m; i++) {
            curators[i]   = aggs[i].curator;
            dpPointers[i] = aggs[i].dpPointer;
            timestamps[i] = aggs[i].timestamp;
        }
    }
}
