// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title DifferentialPrivacyTrustModel
 * @notice
 *   Implements a simple trust model for differential privacy per NIST SP 800-226:
 *   • DataProviders register raw datasets (off-chain pointer).
 *   • DataConsumers request query results; must be authorized.
 *   • Query results are generated off-chain with differential privacy and delivered 
 *     to authorized consumers via an event.
 *
 * Roles:
 *   • DEFAULT_ADMIN_ROLE: can pause/unpause, add/remove providers and consumers.
 *   • PROVIDER_ROLE: may register datasets and publish DP-protected results.
 *   • CONSUMER_ROLE: may request queries and receive results.
 */
contract DifferentialPrivacyTrustModel is AccessControl, Pausable {
    bytes32 public constant PROVIDER_ROLE = keccak256("PROVIDER_ROLE");
    bytes32 public constant CONSUMER_ROLE = keccak256("CONSUMER_ROLE");

    struct Dataset {
        address provider;
        string  pointer;  // off-chain pointer (IPFS hash, URL, etc.)
        bool    exists;
    }

    struct QueryRequest {
        address consumer;
        uint256 datasetId;
        string  query;    // description of query
        bool    fulfilled;
    }

    uint256 private _nextDatasetId = 1;
    uint256 private _nextRequestId = 1;

    mapping(uint256 => Dataset)               private _datasets;
    mapping(uint256 => QueryRequest)          private _requests;
    mapping(address => uint256[])             private _consumerRequests;

    event ProviderAdded(address indexed account);
    event ProviderRemoved(address indexed account);
    event ConsumerAdded(address indexed account);
    event ConsumerRemoved(address indexed account);

    event DatasetRegistered(uint256 indexed datasetId, address indexed provider, string pointer);
    event QueryRequested(uint256 indexed requestId, address indexed consumer, uint256 indexed datasetId, string query);
    event DPResultPublished(uint256 indexed requestId, address indexed consumer, string dpResult);

    modifier onlyProvider() {
        require(hasRole(PROVIDER_ROLE, msg.sender), "Not a provider");
        _;
    }

    modifier onlyConsumer() {
        require(hasRole(CONSUMER_ROLE, msg.sender), "Not a consumer");
        _;
    }

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    /// @notice Add a data provider
    function addProvider(address acct) external onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(PROVIDER_ROLE, acct);
        emit ProviderAdded(acct);
    }

    /// @notice Remove a data provider
    function removeProvider(address acct) external onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(PROVIDER_ROLE, acct);
        emit ProviderRemoved(acct);
    }

    /// @notice Add a data consumer
    function addConsumer(address acct) external onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(CONSUMER_ROLE, acct);
        emit ConsumerAdded(acct);
    }

    /// @notice Remove a data consumer
    function removeConsumer(address acct) external onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(CONSUMER_ROLE, acct);
        emit ConsumerRemoved(acct);
    }

    /// @notice Pause all operations
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause all operations
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @notice Provider registers a new dataset
    function registerDataset(string calldata pointer)
        external
        whenNotPaused
        onlyProvider
        returns (uint256 datasetId)
    {
        datasetId = _nextDatasetId++;
        _datasets[datasetId] = Dataset({
            provider: msg.sender,
            pointer:  pointer,
            exists:   true
        });
        emit DatasetRegistered(datasetId, msg.sender, pointer);
    }

    /// @notice Consumer requests a query; will be fulfilled off-chain
    function requestQuery(uint256 datasetId, string calldata query)
        external
        whenNotPaused
        onlyConsumer
        returns (uint256 requestId)
    {
        require(_datasets[datasetId].exists, "Dataset not found");
        requestId = _nextRequestId++;
        _requests[requestId] = QueryRequest({
            consumer:    msg.sender,
            datasetId:   datasetId,
            query:       query,
            fulfilled:   false
        });
        _consumerRequests[msg.sender].push(requestId);
        emit QueryRequested(requestId, msg.sender, datasetId, query);
    }

    /// @notice Provider publishes differentially private result for a request
    function publishDPResult(uint256 requestId, string calldata dpResult)
        external
        whenNotPaused
        onlyProvider
    {
        QueryRequest storage req = _requests[requestId];
        require(!req.fulfilled, "Already fulfilled");
        require(_datasets[req.datasetId].provider == msg.sender, "Not dataset owner");
        req.fulfilled = true;
        emit DPResultPublished(requestId, req.consumer, dpResult);
    }

    /// @notice Get list of a consumer’s request IDs
    function getConsumerRequests(address consumer) external view returns (uint256[] memory) {
        return _consumerRequests[consumer];
    }

    /// @notice Get details of a specific query request
    function getQueryRequest(uint256 requestId)
        external
        view
        returns (
            address consumer,
            uint256 datasetId,
            string memory query,
            bool fulfilled
        )
    {
        QueryRequest storage req = _requests[requestId];
        return (req.consumer, req.datasetId, req.query, req.fulfilled);
    }
}
