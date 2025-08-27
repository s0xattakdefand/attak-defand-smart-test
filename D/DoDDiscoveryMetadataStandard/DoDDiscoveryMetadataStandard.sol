// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

/**
 * @title DoDDiscoveryMetadataStandard
 * @dev A smart contract for managing DoD Discovery Metadata Standard (DDMS) records.
 * Enables creation, management, and discovery of metadata for DoD data/service assets.
 * THIS IS AN EXAMPLE CONTRACT THAT USES UN-AUDITED CODE.
 * DO NOT USE THIS CODE IN PRODUCTION.
 */
contract DoDDiscoveryMetadataStandard {
    // Struct to represent a DDMS-compliant metadata record
    struct MetadataRecord {
        string title; // Title of the resource (DDMS core element)
        string creator; // Creator or contributor of the resource
        string description; // Description or abstract of the resource
        string date; // Creation or publication date (ISO 8601 format, e.g., "2025-08-27")
        string securityClassification; // Security classification (e.g., Unclassified, Secret)
        mapping(string => string) extensibleAttributes; // Extensible DDMS attributes (e.g., format, subject)
        string[] attributeKeys; // Array to track extensible attribute keys
        address owner; // Owner of the metadata record
        bool exists; // Flag to check if record exists
    }

    // Mapping to store metadata records by their unique ID
    mapping(bytes32 => MetadataRecord) public metadataRecords;

    // Event emitted when a new metadata record is created
    event MetadataRecordCreated(bytes32 indexed recordId, string title, address indexed owner);
    // Event emitted when a metadata record is updated
    event MetadataRecordUpdated(bytes32 indexed recordId, string title, address indexed owner);
    // Event emitted when an extensible attribute is added
    event AttributeAdded(bytes32 indexed recordId, string attributeKey, string attributeValue);

    // Modifier to check if the caller is the owner of the metadata record
    modifier onlyRecordOwner(bytes32 recordId) {
        require(metadataRecords[recordId].owner == msg.sender, "Only the record owner can perform this action");
        require(metadataRecords[recordId].exists, "Metadata record does not exist");
        _;
    }

    /**
     * @dev Creates a new DDMS-compliant metadata record.
     * @param _title The title of the resource.
     * @param _creator The creator or contributor of the resource.
     * @param _description The description or abstract of the resource.
     * @param _date The creation or publication date (ISO 8601 format).
     * @param _securityClassification The security classification of the resource.
     * @return recordId The unique ID of the created metadata record.
     */
    function createMetadataRecord(
        string memory _title,
        string memory _creator,
        string memory _description,
        string memory _date,
        string memory _securityClassification
    ) public returns (bytes32) {
        // Generate a unique ID for the metadata record
        bytes32 recordId = keccak256(abi.encodePacked(_title, msg.sender, block.timestamp));
        
        // Ensure the record doesn't already exist
        require(!metadataRecords[recordId].exists, "Metadata record with this ID already exists");

        // Initialize the metadata record
        MetadataRecord storage newRecord = metadataRecords[recordId];
        newRecord.title = _title;
        newRecord.creator = _creator;
        newRecord.description = _description;
        newRecord.date = _date;
        newRecord.securityClassification = _securityClassification;
        newRecord.owner = msg.sender;
        newRecord.exists = true;

        // Emit event for metadata record creation
        emit MetadataRecordCreated(recordId, _title, msg.sender);

        return recordId;
    }

    /**
     * @dev Updates the core metadata fields of an existing record.
     * @param _recordId The ID of the metadata record to update.
     * @param _title The new title of the resource.
     * @param _creator The new creator or contributor.
     * @param _description The new description or abstract.
     * @param _date The new creation or publication date.
     * @param _securityClassification The new security classification.
     */
    function updateMetadataRecord(
        bytes32 _recordId,
        string memory _title,
        string memory _creator,
        string memory _description,
        string memory _date,
        string memory _securityClassification
    ) public onlyRecordOwner(_recordId) {
        MetadataRecord storage record = metadataRecords[_recordId];
        record.title = _title;
        record.creator = _creator;
        record.description = _description;
        record.date = _date;
        record.securityClassification = _securityClassification;

        // Emit event for metadata record update
        emit MetadataRecordUpdated(_recordId, _title, msg.sender);
    }

    /**
     * @dev Adds an extensible attribute to a metadata record.
     * @param _recordId The ID of the metadata record.
     * @param _attributeKey The key of the extensible attribute (e.g., "format", "subject").
     * @param _attributeValue The value of the extensible attribute.
     */
    function addExtensibleAttribute(
        bytes32 _recordId,
        string memory _attributeKey,
        string memory _attributeValue
    ) public onlyRecordOwner(_recordId) {
        metadataRecords[_recordId].extensibleAttributes[_attributeKey] = _attributeValue;
        metadataRecords[_recordId].attributeKeys.push(_attributeKey);

        // Emit event for attribute addition
        emit AttributeAdded(_recordId, _attributeKey, _attributeValue);
    }

    /**
     * @dev Retrieves the core metadata fields of a record.
     * @param _recordId The ID of the metadata record.
     * @return title The title of the resource.
     * @return creator The creator or contributor.
     * @return description The description or abstract.
     * @return date The creation or publication date.
     * @return securityClassification The security classification.
     * @return owner The owner of the record.
     */
    function getMetadataRecord(bytes32 _recordId)
        public
        view
        returns (
            string memory title,
            string memory creator,
            string memory description,
            string memory date,
            string memory securityClassification,
            address owner
        )
    {
        require(metadataRecords[_recordId].exists, "Metadata record does not exist");
        MetadataRecord storage record = metadataRecords[_recordId];
        return (
            record.title,
            record.creator,
            record.description,
            record.date,
            record.securityClassification,
            record.owner
        );
    }

    /**
     * @dev Retrieves the value of an extensible attribute.
     * @param _recordId The ID of the metadata record.
     * @param _attributeKey The key of the extensible attribute.
     * @return The value of the extensible attribute.
     */
    function getExtensibleAttribute(bytes32 _recordId, string memory _attributeKey)
        public
        view
        returns (string memory)
    {
        require(metadataRecords[_recordId].exists, "Metadata record does not exist");
        return metadataRecords[_recordId].extensibleAttributes[_attributeKey];
    }

    /**
     * @dev Retrieves the list of extensible attribute keys for a metadata record.
     * @param _recordId The ID of the metadata record.
     * @return The array of attribute keys.
     */
    function getAttributeKeys(bytes32 _recordId) public view returns (string[] memory) {
        require(metadataRecords[_recordId].exists, "Metadata record does not exist");
        return metadataRecords[_recordId].attributeKeys;
    }
}
