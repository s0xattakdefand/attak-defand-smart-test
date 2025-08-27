// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

/**
 * @title DoDInformation
 * @dev A smart contract for managing Department of Defense (DoD) information records.
 * Supports secure storage, access control, and verification of DoD information.
 * THIS IS AN EXAMPLE CONTRACT THAT USES UN-AUDITED CODE.
 * DO NOT USE THIS CODE IN PRODUCTION.
 */
contract DoDInformation {
    // Struct to represent a DoD information record
    struct InformationRecord {
        string title; // Title of the information (e.g., "Technical Report")
        string content; // Content or reference to the information (e.g., IPFS hash)
        string classification; // Classification level (e.g., "CUI", "Unclassified", "Secret")
        bool isPubliclyReleasable; // Indicates if cleared for public release per DoDD 5230.09
        address owner; // Owner of the record (e.g., DoD contractor or administrator)
        address[] authorizedUsers; // List of users with access
        mapping(string => string) metadata; // Additional metadata (e.g., "category" => "Technical")
        string[] metadataKeys; // Array to track metadata keys
        bool exists; // Flag to check if record exists
    }

    // Mapping to store information records by their unique ID
    mapping(bytes32 => InformationRecord) public records;

    // Event emitted when a new information record is created
    event RecordCreated(bytes32 indexed recordId, string title, address indexed owner);
    // Event emitted when a record is updated
    event RecordUpdated(bytes32 indexed recordId, string title, address indexed owner);
    // Event emitted when a metadata attribute is added
    event MetadataAdded(bytes32 indexed recordId, string metadataKey, string metadataValue);
    // Event emitted when an authorized user is added
    event AuthorizedUserAdded(bytes32 indexed recordId, address indexed user);
    // Event emitted when public release status is updated
    event PublicReleaseStatusUpdated(bytes32 indexed recordId, bool isPubliclyReleasable);

    // Modifier to check if the caller is the owner of the record
    modifier onlyRecordOwner(bytes32 recordId) {
        require(records[recordId].owner == msg.sender, "Only the record owner can perform this action");
        require(records[recordId].exists, "Record does not exist");
        _;
    }

    // Modifier to check if the caller is an authorized user
    modifier onlyAuthorizedUser(bytes32 recordId) {
        require(records[recordId].exists, "Record does not exist");
        bool isAuthorized = records[recordId].owner == msg.sender;
        if (!isAuthorized) {
            for (uint256 i = 0; i < records[recordId].authorizedUsers.length; i++) {
                if (records[recordId].authorizedUsers[i] == msg.sender) {
                    isAuthorized = true;
                    break;
                }
            }
        }
        require(isAuthorized, "Only authorized users can perform this action");
        _;
    }

    /**
     * @dev Creates a new DoD information record.
     * @param _title The title of the information.
     * @param _content The content or reference (e.g., IPFS hash).
     * @param _classification The classification level (e.g., "CUI", "Unclassified").
     * @param _isPubliclyReleasable Whether the information is cleared for public release.
     * @return recordId The unique ID of the created record.
     */
    function createRecord(
        string memory _title,
        string memory _content,
        string memory _classification,
        bool _isPubliclyReleasable
    ) public returns (bytes32) {
        // Generate a unique ID for the record
        bytes32 recordId = keccak256(abi.encodePacked(_title, msg.sender, block.timestamp));
        
        // Ensure the record doesn't already exist
        require(!records[recordId].exists, "Record with this ID already exists");

        // Initialize the record
        InformationRecord storage newRecord = records[recordId];
        newRecord.title = _title;
        newRecord.content = _content;
        newRecord.classification = _classification;
        newRecord.isPubliclyReleasable = _isPubliclyReleasable;
        newRecord.owner = msg.sender;
        newRecord.exists = true;

        // Emit event for record creation
        emit RecordCreated(recordId, _title, msg.sender);

        return recordId;
    }

    /**
     * @dev Updates the core fields of an existing record.
     * @param _recordId The ID of the record to update.
     * @param _title The new title.
     * @param _content The new content or reference.
     * @param _classification The new classification level.
     */
    function updateRecord(
        bytes32 _recordId,
        string memory _title,
        string memory _content,
        string memory _classification
    ) public onlyRecordOwner(_recordId) {
        InformationRecord storage record = records[_recordId];
        record.title = _title;
        record.content = _content;
        record.classification = _classification;

        // Emit event for record update
        emit RecordUpdated(_recordId, _title, msg.sender);
    }

    /**
     * @dev Updates the public release status of a record.
     * @param _recordId The ID of the record.
     * @param _isPubliclyReleasable The new public release status.
     */
    function updatePublicReleaseStatus(bytes32 _recordId, bool _isPubliclyReleasable) public onlyRecordOwner(_recordId) {
        records[_recordId].isPubliclyReleasable = _isPubliclyReleasable;

        // Emit event for public release status update
        emit PublicReleaseStatusUpdated(_recordId, _isPubliclyReleasable);
    }

    /**
     * @dev Adds a metadata attribute to a record.
     * @param _recordId The ID of the record.
     * @param _metadataKey The key of the metadata (e.g., "category").
     * @param _metadataValue The value of the metadata.
     */
    function addMetadata(
        bytes32 _recordId,
        string memory _metadataKey,
        string memory _metadataValue
    ) public onlyRecordOwner(_recordId) {
        records[_recordId].metadata[_metadataKey] = _metadataValue;
        records[_recordId].metadataKeys.push(_metadataKey);

        // Emit event for metadata addition
        emit MetadataAdded(_recordId, _metadataKey, _metadataValue);
    }

    /**
     * @dev Adds an authorized user to a record.
     * @param _recordId The ID of the record.
     * @param _user The address of the user to authorize.
     */
    function addAuthorizedUser(bytes32 _recordId, address _user) public onlyRecordOwner(_recordId) {
        require(_user != address(0), "Invalid user address");
        // Check if user is already authorized
        for (uint256 i = 0; i < records[_recordId].authorizedUsers.length; i++) {
            require(records[_recordId].authorizedUsers[i] != _user, "User already authorized");
        }
        records[_recordId].authorizedUsers.push(_user);

        // Emit event for authorized user addition
        emit AuthorizedUserAdded(_recordId, _user);
    }

    /**
     * @dev Retrieves the core fields of a record.
     * @param _recordId The ID of the record.
     * @return title The title of the record.
     * @return content The content or reference.
     * @return classification The classification level.
     * @return isPubliclyReleasable The public release status.
     * @return owner The owner of the record.
     */
    function getRecord(bytes32 _recordId)
        public
        view
        onlyAuthorizedUser(_recordId)
        returns (
            string memory title,
            string memory content,
            string memory classification,
            bool isPubliclyReleasable,
            address owner
        )
    {
        require(records[_recordId].exists, "Record does not exist");
        InformationRecord storage record = records[_recordId];
        return (
            record.title,
            record.content,
            record.classification,
            record.isPubliclyReleasable,
            record.owner
        );
    }

    /**
     * @dev Retrieves the content of a record if publicly releasable.
     * @param _recordId The ID of the record.
     * @return The content or reference.
     */
    function getPublicRecordContent(bytes32 _recordId) public view returns (string memory) {
        require(records[_recordId].exists, "Record does not exist");
        require(records[_recordId].isPubliclyReleasable, "Record is not publicly releasable");
        return records[_recordId].content;
    }

    /**
     * @dev Retrieves the value of a metadata attribute.
     * @param _recordId The ID of the record.
     * @param _metadataKey The key of the metadata.
     * @return The value of the metadata.
     */
    function getMetadata(bytes32 _recordId, string memory _metadataKey)
        public
        view
        onlyAuthorizedUser(_recordId)
        returns (string memory)
    {
        require(records[_recordId].exists, "Record does not exist");
        return records[_recordId].metadata[_metadataKey];
    }

    /**
     * @dev Retrieves the list of metadata keys for a record.
     * @param _recordId The ID of the record.
     * @return The array of metadata keys.
     */
    function getMetadataKeys(bytes32 _recordId)
        public
        view
        onlyAuthorizedUser(_recordId)
        returns (string[] memory)
    {
        require(records[_recordId].exists, "Record does not exist");
        return records[_recordId].metadataKeys;
    }

    /**
     * @dev Retrieves the list of authorized users for a record.
     * @param _recordId The ID of the record.
     * @return The array of authorized user addresses.
     */
    function getAuthorizedUsers(bytes32 _recordId)
        public
        view
        onlyRecordOwner(_recordId)
        returns (address[] memory)
    {
        require(records[_recordId].exists, "Record does not exist");
        return records[_recordId].authorizedUsers;
    }
}
