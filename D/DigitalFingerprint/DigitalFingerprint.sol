// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

/**
 * @title DigitalFingerprint
 * @dev A smart contract for managing digital fingerprints (hashes) to ensure data integrity and authenticity.
 * Supports fingerprint creation, verification, and chain-of-custody tracking with access control.
 * THIS IS AN EXAMPLE CONTRACT FOR EDUCATIONAL PURPOSES ONLY AND USES UN-AUDITED CODE.
 * DO NOT USE THIS CODE IN PRODUCTION.
 */
contract DigitalFingerprint {
    // Struct to represent a chain-of-custody entry
    struct CustodyEntry {
        address custodian; // Address of the custodian or modifier
        string action; // Description of the action (e.g., "Fingerprint created", "Ownership transferred")
        uint256 timestamp; // Timestamp of the action
    }

    // Struct to represent a digital fingerprint record
    struct FingerprintRecord {
        bytes32 fingerprint; // Keccak-256 hash of the data (digital fingerprint)
        string description; // Description of the data (e.g., "Document fingerprint")
        address owner; // Current owner of the fingerprint record
        address[] authorizedVerifiers; // List of addresses authorized to verify the fingerprint
        CustodyEntry[] custodyLog; // Chain-of-custody log
        uint256 timestamp; // Timestamp of fingerprint creation
        bool exists; // Flag to check if record exists
    }

    // Mapping to store fingerprint records by their unique ID
    mapping(bytes32 => FingerprintRecord) public fingerprintRecords;
    // Mapping to track fingerprint records by owner
    mapping(address => bytes32[]) public ownerFingerprints;

    // Event emitted when a new fingerprint is created
    event FingerprintCreated(bytes32 indexed recordId, bytes32 fingerprint, address indexed owner, string description);
    // Event emitted when a fingerprint description is updated
    event FingerprintUpdated(bytes32 indexed recordId, string newDescription);
    // Event emitted when fingerprint ownership is transferred
    event FingerprintTransferred(bytes32 indexed recordId, address indexed newOwner);
    // Event emitted when a verifier is authorized
    event VerifierAuthorized(bytes32 indexed recordId, address indexed verifier);
    // Event emitted when a fingerprint is verified
    event FingerprintVerified(bytes32 indexed recordId, address indexed verifier, bool isValid);
    // Event emitted when a custody entry is added
    event CustodyUpdated(bytes32 indexed recordId, address indexed custodian, string action);

    // Modifier to check if the caller is the owner of the fingerprint record
    modifier onlyOwner(bytes32 recordId) {
        require(fingerprintRecords[recordId].owner == msg.sender, "Only the owner can perform this action");
        require(fingerprintRecords[recordId].exists, "Fingerprint record does not exist");
        _;
    }

    // Modifier to check if the caller is an authorized verifier or owner
    modifier onlyAuthorized(bytes32 recordId) {
        require(fingerprintRecords[recordId].exists, "Fingerprint record does not exist");
        bool isAuthorized = fingerprintRecords[recordId].owner == msg.sender;
        if (!isAuthorized) {
            for (uint256 i = 0; i < fingerprintRecords[recordId].authorizedVerifiers.length; i++) {
                if (fingerprintRecords[recordId].authorizedVerifiers[i] == msg.sender) {
                    isAuthorized = true;
                    break;
                }
            }
        }
        require(isAuthorized, "Only authorized verifiers or owner can perform this action");
        _;
    }

    /**
     * @dev Creates a new digital fingerprint record.
     * @param _data The data to hash (e.g., document, image).
     * @param _description The description of the data.
     * @return recordId The unique ID of the fingerprint record.
     */
    function createFingerprint(bytes memory _data, string memory _description) public returns (bytes32) {
        require(_data.length > 0, "Data cannot be empty");
        require(bytes(_description).length > 0, "Description cannot be empty");

        // Generate the Keccak-256 fingerprint
        bytes32 fingerprint = keccak256(_data);
        // Generate a unique record ID
        bytes32 recordId = keccak256(abi.encodePacked(fingerprint, msg.sender, block.timestamp));
        
        // Ensure the record doesn't already exist
        require(!fingerprintRecords[recordId].exists, "Fingerprint record with this ID already exists");

        // Initialize the fingerprint record
        FingerprintRecord storage newRecord = fingerprintRecords[recordId];
        newRecord.fingerprint = fingerprint;
        newRecord.description = _description;
        newRecord.owner = msg.sender;
        newRecord.timestamp = block.timestamp;
        newRecord.exists = true;

        // Initialize the custody log with the creation entry
        newRecord.custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "Fingerprint created",
            timestamp: block.timestamp
        }));

        // Add record ID to owner's list
        ownerFingerprints[msg.sender].push(recordId);

        // Emit events for fingerprint creation and custody update
        emit FingerprintCreated(recordId, fingerprint, msg.sender, _description);
        emit CustodyUpdated(recordId, msg.sender, "Fingerprint created");

        return recordId;
    }

    /**
     * @dev Updates the description of an existing fingerprint record.
     * @param _recordId The ID of the fingerprint record.
     * @param _newDescription The new description for the fingerprint record.
     */
    function updateFingerprintDescription(bytes32 _recordId, string memory _newDescription) public onlyOwner(_recordId) {
        require(bytes(_newDescription).length > 0, "Description cannot be empty");
        fingerprintRecords[_recordId].description = _newDescription;

        // Add custody log entry for update
        fingerprintRecords[_recordId].custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "Description updated",
            timestamp: block.timestamp
        }));

        // Emit events for fingerprint update and custody update
        emit FingerprintUpdated(_recordId, _newDescription);
        emit CustodyUpdated(_recordId, msg.sender, "Description updated");
    }

    /**
     * @dev Transfers ownership of a fingerprint record to a new address.
     * @param _recordId The ID of the fingerprint record.
     * @param _newOwner The address of the new owner.
     */
    function transferFingerprintOwnership(bytes32 _recordId, address _newOwner) public onlyOwner(_recordId) {
        require(_newOwner != address(0), "New owner address cannot be zero");
        require(_newOwner != fingerprintRecords[_recordId].owner, "New owner must be different");

        // Update ownership
        fingerprintRecords[_recordId].owner = _newOwner;

        // Add custody log entry for transfer
        fingerprintRecords[_recordId].custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "Ownership transferred to new owner",
            timestamp: block.timestamp
        }));

        // Update ownerFingerprints mappings
        bytes32[] storage ownerRecords = ownerFingerprints[msg.sender];
        for (uint256 i = 0; i < ownerRecords.length; i++) {
            if (ownerRecords[i] == _recordId) {
                ownerRecords[i] = ownerRecords[ownerRecords.length - 1];
                ownerRecords.pop();
                break;
            }
        }
        ownerFingerprints[_newOwner].push(_recordId);

        // Emit events for ownership transfer and custody update
        emit FingerprintTransferred(_recordId, _newOwner);
        emit CustodyUpdated(_recordId, msg.sender, "Ownership transferred to new owner");
    }

    /**
     * @dev Authorizes a verifier to access a fingerprint record.
     * @param _recordId The ID of the fingerprint record.
     * @param _verifier The address of the verifier to authorize.
     */
    function authorizeVerifier(bytes32 _recordId, address _verifier) public onlyOwner(_recordId) {
        require(_verifier != address(0), "Verifier address cannot be zero");
        // Check if verifier is already authorized
        for (uint256 i = 0; i < fingerprintRecords[_recordId].authorizedVerifiers.length; i++) {
            require(fingerprintRecords[_recordId].authorizedVerifiers[i] != _verifier, "Verifier already authorized");
        }
        fingerprintRecords[_recordId].authorizedVerifiers.push(_verifier);

        // Add custody log entry for authorization
        fingerprintRecords[_recordId].custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "Verifier authorized",
            timestamp: block.timestamp
        }));

        // Emit events for verifier authorization and custody update
        emit VerifierAuthorized(_recordId, _verifier);
        emit CustodyUpdated(_recordId, msg.sender, "Verifier authorized");
    }

    /**
     * @dev Verifies a fingerprint against provided data.
     * @param _recordId The ID of the fingerprint record.
     * @param _data The data to verify against the stored fingerprint.
     * @return isValid True if the data matches the stored fingerprint, false otherwise.
     */
    function verifyFingerprint(bytes32 _recordId, bytes memory _data) public onlyAuthorized(_recordId) returns (bool) {
        require(fingerprintRecords[_recordId].exists, "Fingerprint record does not exist");
        require(_data.length > 0, "Data cannot be empty");

        // Compute the hash of the provided data
        bytes32 computedFingerprint = keccak256(_data);
        bool isValid = (computedFingerprint == fingerprintRecords[_recordId].fingerprint);

        // Emit event for fingerprint verification
        emit FingerprintVerified(_recordId, msg.sender, isValid);

        return isValid;
    }

    /**
     * @dev Retrieves the details of a fingerprint record.
     * @param _recordId The ID of the fingerprint record.
     * @return fingerprint The stored fingerprint (hash).
     * @return description The description of the data.
     * @return owner The owner of the fingerprint record.
     * @return timestamp The timestamp of fingerprint creation.
     */
    function getFingerprint(bytes32 _recordId)
        public
        view
        onlyAuthorized(_recordId)
        returns (
            bytes32 fingerprint,
            string memory description,
            address owner,
            uint256 timestamp
        )
    {
        require(fingerprintRecords[_recordId].exists, "Fingerprint record does not exist");
        FingerprintRecord storage record = fingerprintRecords[_recordId];
        return (
            record.fingerprint,
            record.description,
            record.owner,
            record.timestamp
        );
    }

    /**
     * @dev Retrieves the list of authorized verifiers for a fingerprint record.
     * @param _recordId The ID of the fingerprint record.
     * @return The array of authorized verifier addresses.
     */
    function getAuthorizedVerifiers(bytes32 _recordId)
        public
        view
        onlyOwner(_recordId)
        returns (address[] memory)
    {
        return fingerprintRecords[_recordId].authorizedVerifiers;
    }

    /**
     * @dev Retrieves the chain-of-custody log for a fingerprint record.
     * @param _recordId The ID of the fingerprint record.
     * @return custodians The array of custodian addresses.
     * @return actions The array of action descriptions.
     * @return timestamps The array of action timestamps.
     */
    function getCustodyLog(bytes32 _recordId)
        public
        view
        onlyAuthorized(_recordId)
        returns (
            address[] memory custodians,
            string[] memory actions,
            uint256[] memory timestamps
        )
    {
        require(fingerprintRecords[_recordId].exists, "Fingerprint record does not exist");
        FingerprintRecord storage record = fingerprintRecords[_recordId];
        uint256 logLength = record.custodyLog.length;

        custodians = new address[](logLength);
        actions = new string[](logLength);
        timestamps = new uint256[](logLength);

        for (uint256 i = 0; i < logLength; i++) {
            custodians[i] = record.custodyLog[i].custodian;
            actions[i] = record.custodyLog[i].action;
            timestamps[i] = record.custodyLog[i].timestamp;
        }

        return (custodians, actions, timestamps);
    }

    /**
     * @dev Retrieves the list of fingerprint record IDs for a given owner.
     * @param _owner The address of the owner.
     * @return The array of fingerprint record IDs.
     */
    function getOwnerFingerprints(address _owner) public view returns (bytes32[] memory) {
        return ownerFingerprints[_owner];
    }
}