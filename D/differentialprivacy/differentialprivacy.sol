// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

/**
 * @title DifferentialPrivacy
 * @dev A smart contract for managing datasets with differential privacy mechanisms.
 * Supports dataset registration, query processing with noise addition, and access control.
 * THIS IS AN EXAMPLE CONTRACT FOR EDUCATIONAL PURPOSES ONLY AND USES UN-AUDITED CODE.
 * DO NOT USE THIS CODE IN PRODUCTION.
 */
contract DifferentialPrivacy {
    // Struct to represent a dataset
    struct Dataset {
        string datasetName; // Name of the dataset (e.g., "DoD Personnel Records")
        string description; // Description of the dataset
        string sensitivity; // Sensitivity level (e.g., "Low", "High")
        address dataOwner; // Owner of the dataset
        address[] authorizedAnalysts; // List of authorized analysts
        mapping(string => string) privacyMechanisms; // Privacy mechanisms (e.g., "Laplace" => "Epsilon=0.1")
        string[] mechanismKeys; // Array to track mechanism keys
        bool exists; // Flag to check if dataset exists
    }

    // Struct to represent a query result
    struct QueryResult {
        bytes32 datasetId; // ID of the dataset
        string queryDescription; // Description of the query (e.g., "Average age")
        uint256 trueValue; // True query result (before noise)
        uint256 noisyValue; // Noisy query result (after applying differential privacy)
        bool exists; // Flag to check if query result exists
    }

    // Mapping to store datasets by their unique ID
    mapping(bytes32 => Dataset) public datasets;
    // Mapping to store query results by their unique ID
    mapping(bytes32 => QueryResult) public queryResults;

    // Event emitted when a new dataset is registered
    event DatasetRegistered(bytes32 indexed datasetId, string datasetName, address indexed dataOwner);
    // Event emitted when a dataset is updated
    event DatasetUpdated(bytes32 indexed datasetId, string datasetName, address indexed dataOwner);
    // Event emitted when a privacy mechanism is added
    event PrivacyMechanismAdded(bytes32 indexed datasetId, string mechanismKey, string mechanismValue);
    // Event emitted when an analyst is authorized
    event AnalystAuthorized(bytes32 indexed datasetId, address indexed analyst);
    // Event emitted when a query is processed
    event QueryProcessed(bytes32 indexed queryId, bytes32 indexed datasetId, string queryDescription, uint256 noisyValue);

    // Modifier to check if the caller is the data owner
    modifier onlyDataOwner(bytes32 datasetId) {
        require(datasets[datasetId].dataOwner == msg.sender, "Only the data owner can perform this action");
        require(datasets[datasetId].exists, "Dataset does not exist");
        _;
    }

    // Modifier to check if the caller is an authorized analyst
    modifier onlyAuthorizedAnalyst(bytes32 datasetId) {
        require(datasets[datasetId].exists, "Dataset does not exist");
        bool isAuthorized = datasets[datasetId].dataOwner == msg.sender;
        if (!isAuthorized) {
            for (uint256 i = 0; i < datasets[datasetId].authorizedAnalysts.length; i++) {
                if (datasets[datasetId].authorizedAnalysts[i] == msg.sender) {
                    isAuthorized = true;
                    break;
                }
            }
        }
        require(isAuthorized, "Only authorized analysts can perform this action");
        _;
    }

    /**
     * @dev Registers a new dataset.
     * @param _datasetName The name of the dataset.
     * @param _description The description of the dataset.
     * @param _sensitivity The sensitivity level (e.g., "Low", "High").
     * @return datasetId The unique ID of the created dataset.
     */
    function registerDataset(
        string memory _datasetName,
        string memory _description,
        string memory _sensitivity
    ) public returns (bytes32) {
        // Generate a unique ID for the dataset
        bytes32 datasetId = keccak256(abi.encodePacked(_datasetName, msg.sender, block.timestamp));
        
        // Ensure the dataset doesn't already exist
        require(!datasets[datasetId].exists, "Dataset with this ID already exists");

        // Initialize the dataset
        Dataset storage newDataset = datasets[datasetId];
        newDataset.datasetName = _datasetName;
        newDataset.description = _description;
        newDataset.sensitivity = _sensitivity;
        newDataset.dataOwner = msg.sender;
        newDataset.exists = true;
        newDataset.authorizedAnalysts.push(msg.sender); // Data owner is an initial analyst

        // Emit event for dataset registration
        emit DatasetRegistered(datasetId, _datasetName, msg.sender);

        return datasetId;
    }

    /**
     * @dev Updates the description of an existing dataset.
     * @param _datasetId The ID of the dataset to update.
     * @param _newDescription The new description for the dataset.
     */
    function updateDatasetDescription(bytes32 _datasetId, string memory _newDescription) public onlyDataOwner(_datasetId) {
        datasets[_datasetId].description = _newDescription;

        // Emit event for dataset update
        emit DatasetUpdated(_datasetId, datasets[_datasetId].datasetName, msg.sender);
    }

    /**
     * @dev Adds a privacy mechanism to a dataset.
     * @param _datasetId The ID of the dataset.
     * @param _mechanismKey The key of the privacy mechanism (e.g., "Laplace").
     * @param _mechanismValue The value or parameters of the mechanism (e.g., "Epsilon=0.1").
     */
    function addPrivacyMechanism(
        bytes32 _datasetId,
        string memory _mechanismKey,
        string memory _mechanismValue
    ) public onlyDataOwner(_datasetId) {
        datasets[_datasetId].privacyMechanisms[_mechanismKey] = _mechanismValue;
        datasets[_datasetId].mechanismKeys.push(_mechanismKey);

        // Emit event for privacy mechanism addition
        emit PrivacyMechanismAdded(_datasetId, _mechanismKey, _mechanismValue);
    }

    /**
     * @dev Authorizes an analyst to query a dataset.
     * @param _datasetId The ID of the dataset.
     * @param _analyst The address of the analyst to authorize.
     */
    function authorizeAnalyst(bytes32 _datasetId, address _analyst) public onlyDataOwner(_datasetId) {
        require(_analyst != address(0), "Invalid analyst address");
        // Check if analyst is already authorized
        for (uint256 i = 0; i < datasets[_datasetId].authorizedAnalysts.length; i++) {
            require(datasets[_datasetId].authorizedAnalysts[i] != _analyst, "Analyst already authorized");
        }
        datasets[_datasetId].authorizedAnalysts.push(_analyst);

        // Emit event for analyst authorization
        emit AnalystAuthorized(_datasetId, _analyst);
    }

    /**
     * @dev Processes a query with differential privacy (Laplace mechanism example).
     * @param _datasetId The ID of the dataset.
     * @param _queryDescription The description of the query (e.g., "Average age").
     * @param _trueValue The true query result (simulated input).
     * @param _epsilon The privacy parameter (controls noise level, e.g., 0.1).
     * @return queryId The unique ID of the query result.
     */
    function processQuery(
        bytes32 _datasetId,
        string memory _queryDescription,
        uint256 _trueValue,
        uint256 _epsilon
    ) public onlyAuthorizedAnalyst(_datasetId) returns (bytes32) {
        require(_epsilon > 0, "Epsilon must be greater than 0");
        require(datasets[_datasetId].exists, "Dataset does not exist");

        // Generate a unique ID for the query result
        bytes32 queryId = keccak256(abi.encodePacked(_datasetId, _queryDescription, msg.sender, block.timestamp));

        // Simulate adding Laplace noise (simplified for Solidity)
        // In a real implementation, noise would be generated off-chain or via an oracle
        uint256 noise = _epsilon > 0 ? (block.timestamp % (2 * _epsilon)) - _epsilon : 0; // Simplified pseudo-random noise
        uint256 noisyValue = _trueValue + noise;

        // Store the query result
        queryResults[queryId] = QueryResult({
            datasetId: _datasetId,
            queryDescription: _queryDescription,
            trueValue: _trueValue,
            noisyValue: noisyValue,
            exists: true
        });

        // Emit event for query processing
        emit QueryProcessed(queryId, _datasetId, _queryDescription, noisyValue);

        return queryId;
    }

    /**
     * @dev Retrieves the details of a dataset.
     * @param _datasetId The ID of the dataset.
     * @return datasetName The name of the dataset.
     * @return description The description of the dataset.
     * @return sensitivity The sensitivity level.
     * @return dataOwner The data owner.
     */
    function getDataset(bytes32 _datasetId)
        public
        view
        onlyAuthorizedAnalyst(_datasetId)
        returns (
            string memory datasetName,
            string memory description,
            string memory sensitivity,
            address dataOwner
        )
    {
        require(datasets[_datasetId].exists, "Dataset does not exist");
        Dataset storage dataset = datasets[_datasetId];
        return (
            dataset.datasetName,
            dataset.description,
            dataset.sensitivity,
            dataset.dataOwner
        );
    }

    /**
     * @dev Retrieves the value of a specific privacy mechanism.
     * @param _datasetId The ID of the dataset.
     * @param _mechanismKey The key of the privacy mechanism.
     * @return The value of the privacy mechanism.
     */
    function getPrivacyMechanism(bytes32 _datasetId, string memory _mechanismKey)
        public
        view
        onlyAuthorizedAnalyst(_datasetId)
        returns (string memory)
    {
        require(datasets[_datasetId].exists, "Dataset does not exist");
        return datasets[_datasetId].privacyMechanisms[_mechanismKey];
    }

    /**
     * @dev Retrieves the list of privacy mechanism keys for a dataset.
     * @param _datasetId The ID of the dataset.
     * @return The array of mechanism keys.
     */
    function getMechanismKeys(bytes32 _datasetId)
        public
        view
        onlyAuthorizedAnalyst(_datasetId)
        returns (string[] memory)
    {
        require(datasets[_datasetId].exists, "Dataset does not exist");
        return datasets[_datasetId].mechanismKeys;
    }

    /**
     * @dev Retrieves the list of authorized analysts for a dataset.
     * @param _datasetId The ID of the dataset.
     * @return The array of authorized analyst addresses.
     */
    function getAuthorizedAnalysts(bytes32 _datasetId)
        public
        view
        onlyDataOwner(_datasetId)
        returns (address[] memory)
    {
        require(datasets[_datasetId].exists, "Dataset does not exist");
        return datasets[_datasetId].authorizedAnalysts;
    }

    /**
     * @dev Retrieves the details of a query result.
     * @param _queryId The ID of the query result.
     * @return datasetId The ID of the dataset.
     * @return queryDescription The query description.
     * @return trueValue The true query result.
     * @return noisyValue The noisy query result.
     */
    function getQueryResult(bytes32 _queryId)
        public
        view
        returns (
            bytes32 datasetId,
            string memory queryDescription,
            uint256 trueValue,
            uint256 noisyValue
        )
    {
        require(queryResults[_queryId].exists, "Query result does not exist");
        // Only allow access if the caller is an authorized analyst for the dataset
        require(
            datasets[queryResults[_queryId].datasetId].dataOwner == msg.sender ||
            isAnalystAuthorized(queryResults[_queryId].datasetId, msg.sender),
            "Not authorized to view query result"
        );
        QueryResult storage result = queryResults[_queryId];
        return (
            result.datasetId,
            result.queryDescription,
            result.trueValue,
            result.noisyValue
        );
    }

    /**
     * @dev Internal function to check if an address is an authorized analyst.
     * @param _datasetId The ID of the dataset.
     * @param _analyst The address to check.
     * @return Whether the address is an authorized analyst.
     */
    function isAnalystAuthorized(bytes32 _datasetId, address _analyst) internal view returns (bool) {
        for (uint256 i = 0; i < datasets[_datasetId].authorizedAnalysts.length; i++) {
            if (datasets[_datasetId].authorizedAnalysts[i] == _analyst) {
                return true;
            }
        }
        return false;
    }
}
