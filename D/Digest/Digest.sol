// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

/**
 * @title Digest
 * @dev A smart contract for managing cryptographic digests (hashes) to ensure data integrity.
 * Supports digest creation, storage, and verification with access control.
 * THIS IS AN EXAMPLE CONTRACT FOR EDUCATIONAL PURPOSES ONLY AND USES UN-AUDITED CODE.
 * DO NOT USE THIS CODE IN PRODUCTION.
 */
contract Digest {
    // Struct to represent a digest record
    struct DigestRecord {
        bytes32 digest; // Keccak-256 hash of the data
        string description; // Description of the data (e.g., "Contract document")
        address owner; // Owner of the digest record
        uint256 timestamp; // Timestamp of digest creation
        bool exists; // Flag to check if record exists
    }

    // Mapping to store digest records by their unique ID
    mapping(bytes32 => DigestRecord) public digestRecords;
    // Mapping to track digests by owner
    mapping(address => bytes32[]) public ownerDigests;

    // Event emitted when a new digest is created
    event DigestCreated(bytes32 indexed recordId, bytes32 digest, address indexed owner, string description);
    // Event emitted when a digest is updated
    event DigestUpdated(bytes32 indexed recordId, string newDescription);
    // Event emitted when a digest is verified
    event DigestVerified(bytes32 indexed recordId, bool isValid);

    // Modifier to check if the caller is the owner of the digest record
    modifier onlyOwner(bytes32 recordId) {
        require(digestRecords[recordId].owner == msg.sender, "Only the owner can perform this action");
        require(digestRecords[recordId].exists, "Digest record does not exist");
        _;
    }

    /**
     * @dev Creates a new digest record for given data.
     * @param _data The data to hash (e.g., document, message).
     * @param _description The description of the data.
     * @return recordId The unique ID of the digest record.
     */
    function createDigest(bytes memory _data, string memory _description) public returns (bytes32) {
        require(_data.length > 0, "Data cannot be empty");
        require(bytes(_description).length > 0, "Description cannot be empty");

        // Generate the Keccak-256 digest
        bytes32 digest = keccak256(_data);
        // Generate a unique record ID
        bytes32 recordId = keccak256(abi.encodePacked(digest, msg.sender, block.timestamp));
        
        // Ensure the record doesn't already exist
        require(!digestRecords[recordId].exists, "Digest record with this ID already exists");

        // Initialize the digest record
        DigestRecord storage newRecord = digestRecords[recordId];
        newRecord.digest = digest;
        newRecord.description = _description;
        newRecord.owner = msg.sender;
        newRecord.timestamp = block.timestamp;
        newRecord.exists = true;

        // Add record ID to owner's list
        ownerDigests[msg.sender].push(recordId);

        // Emit event for digest creation
        emit DigestCreated(recordId, digest, msg.sender, _description);

        return recordId;
    }

    /**
     * @dev Updates the description of an existing digest record.
     * @param _recordId The ID of the digest record.
     * @param _newDescription The new description for the digest record.
     */
    function updateDigestDescription(bytes32 _recordId, string memory _newDescription) public onlyOwner(_recordId) {
        require(bytes(_newDescription).length > 0, "Description cannot be empty");
        digestRecords[_recordId].description = _newDescription;

        // Emit event for digest update
        emit DigestUpdated(_recordId, _newDescription);
    }

    /**
     * @dev Verifies if the provided data matches the stored digest.
     * @param _recordId The ID of the digest record.
     * @param _data The data to verify against the stored digest.
     * @return isValid True if the data matches the stored digest, false otherwise.
     */
    function verifyDigest(bytes32 _recordId, bytes memory _data) public returns (bool) {
        require(digestRecords[_recordId].exists, "Digest record does not exist");
        require(_data.length > 0, "Data cannot be empty");

        // Compute the hash of the provided data
        bytes32 computedDigest = keccak256(_data);
        bool isValid = (computedDigest == digestRecords[_recordId].digest);

        // Emit event for digest verification
        emit DigestVerified(_recordId, isValid);

        return isValid;
    }

    /**
     * @dev Retrieves the details of a digest record.
     * @param _recordId The ID of the digest record.
     * @return digest The stored digest.
     * @return description The description of the data.
     * @return owner The owner of the digest record.
     * @return timestamp The timestamp of digest creation.
     */
    function getDigest(bytes32 _recordId)
        public
        view
        returns (
            bytes32 digest,
            string memory description,
            address owner,
            uint256 timestamp
        )
    {
        require(digestRecords[_recordId].exists, "Digest record does not exist");
        DigestRecord storage record = digestRecords[_recordId];
        return (
            record.digest,
            record.description,
            record.owner,
            record.timestamp
        );
    }

    /**
     * @dev Retrieves the list of digest record IDs for a given owner.
     * @param _owner The address of the owner.
     * @return The array of digest record IDs.
     */
    function getOwnerDigests(address _owner) public view returns (bytes32[] memory) {
        return ownerDigests[_owner];
    }
}