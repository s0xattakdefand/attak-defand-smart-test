// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

/**
 * @title DigitalEvidence
 * @dev A smart contract for managing digital evidence with cryptographic hashes and signatures.
 * Supports evidence registration, verification, and chain-of-custody tracking with access control.
 * THIS IS AN EXAMPLE CONTRACT FOR EDUCATIONAL PURPOSES ONLY AND USES UN-AUDITED CODE.
 * DO NOT USE THIS CODE IN PRODUCTION.
 */
contract DigitalEvidence {
    // Struct to represent a chain-of-custody entry
    struct CustodyEntry {
        address custodian; // Address of the custodian or modifier
        string action; // Description of the action (e.g., "Evidence submitted", "Ownership transferred")
        uint256 timestamp; // Timestamp of the action
    }

    // Struct to represent a digital evidence record
    struct EvidenceRecord {
        bytes32 dataHash; // Keccak-256 hash of the evidence data
        string description; // Description of the evidence (e.g., "Forensic report")
        bytes signature; // Optional digital signature (r, s, v components)
        address owner; // Current owner of the evidence record
        address[] authorizedVerifiers; // List of addresses authorized to verify the evidence
        CustodyEntry[] custodyLog; // Chain-of-custody log
        uint256 timestamp; // Timestamp of evidence creation
        bool exists; // Flag to check if record exists
    }

    // Mapping to store evidence records by their unique ID
    mapping(bytes32 => EvidenceRecord) public evidenceRecords;
    // Mapping to track evidence records by owner
    mapping(address => bytes32[]) public ownerEvidence;

    // Event emitted when a new evidence record is created
    event EvidenceCreated(bytes32 indexed recordId, bytes32 dataHash, address indexed owner, string description);
    // Event emitted when an evidence record is updated
    event EvidenceUpdated(bytes32 indexed recordId, string newDescription);
    // Event emitted when evidence ownership is transferred
    event EvidenceTransferred(bytes32 indexed recordId, address indexed newOwner);
    // Event emitted when a verifier is authorized
    event VerifierAuthorized(bytes32 indexed recordId, address indexed verifier);
    // Event emitted when an evidence record is verified
    event EvidenceVerified(bytes32 indexed recordId, address indexed verifier, bool isValid);
    // Event emitted when a custody entry is added
    event CustodyUpdated(bytes32 indexed recordId, address indexed custodian, string action);

    // Modifier to check if the caller is the owner of the evidence record
    modifier onlyOwner(bytes32 recordId) {
        require(evidenceRecords[recordId].owner == msg.sender, "Only the owner can perform this action");
        require(evidenceRecords[recordId].exists, "Evidence record does not exist");
        _;
    }

    // Modifier to check if the caller is an authorized verifier or owner
    modifier onlyAuthorized(bytes32 recordId) {
        require(evidenceRecords[recordId].exists, "Evidence record does not exist");
        bool isAuthorized = evidenceRecords[recordId].owner == msg.sender;
        if (!isAuthorized) {
            for (uint256 i = 0; i < evidenceRecords[recordId].authorizedVerifiers.length; i++) {
                if (evidenceRecords[recordId].authorizedVerifiers[i] == msg.sender) {
                    isAuthorized = true;
                    break;
                }
            }
        }
        require(isAuthorized, "Only authorized verifiers or owner can perform this action");
        _;
    }

    /**
     * @dev Creates a new digital evidence record.
     * @param _data The evidence data to hash (e.g., document, image).
     * @param _signature Optional digital signature of the data (r, s, v components; pass empty bytes if not used).
     * @param _description The description of the evidence.
     * @return recordId The unique ID of the evidence record.
     */
    function createEvidence(
        bytes memory _data,
        bytes memory _signature,
        string memory _description
    ) public returns (bytes32) {
        require(_data.length > 0, "Data cannot be empty");
        require(bytes(_description).length > 0, "Description cannot be empty");
        if (_signature.length > 0) {
            require(_signature.length == 65, "Invalid signature length");
        }

        // Generate the Keccak-256 hash of the data
        bytes32 dataHash = keccak256(_data);
        // Generate a unique record ID
        bytes32 recordId = keccak256(abi.encodePacked(dataHash, msg.sender, block.timestamp));
        
        // Ensure the record doesn't already exist
        require(!evidenceRecords[recordId].exists, "Evidence record with this ID already exists");

        // Initialize the evidence record
        EvidenceRecord storage newRecord = evidenceRecords[recordId];
        newRecord.dataHash = dataHash;
        newRecord.description = _description;
        newRecord.signature = _signature;
        newRecord.owner = msg.sender;
        newRecord.timestamp = block.timestamp;
        newRecord.exists = true;

        // Initialize the custody log with the creation entry
        newRecord.custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "Evidence submitted",
            timestamp: block.timestamp
        }));

        // Add record ID to owner's list
        ownerEvidence[msg.sender].push(recordId);

        // Emit events for evidence creation and custody update
        emit EvidenceCreated(recordId, dataHash, msg.sender, _description);
        emit CustodyUpdated(recordId, msg.sender, "Evidence submitted");

        return recordId;
    }

    /**
     * @dev Updates the description of an existing evidence record.
     * @param _recordId The ID of the evidence record.
     * @param _newDescription The new description for the evidence record.
     */
    function updateEvidenceDescription(bytes32 _recordId, string memory _newDescription) public onlyOwner(_recordId) {
        require(bytes(_newDescription).length > 0, "Description cannot be empty");
        evidenceRecords[_recordId].description = _newDescription;

        // Add custody log entry for update
        evidenceRecords[_recordId].custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "Description updated",
            timestamp: block.timestamp
        }));

        // Emit events for evidence update and custody update
        emit EvidenceUpdated(_recordId, _newDescription);
        emit CustodyUpdated(_recordId, msg.sender, "Description updated");
    }

    /**
     * @dev Transfers ownership of an evidence record to a new address.
     * @param _recordId The ID of the evidence record.
     * @param _newOwner The address of the new owner.
     */
    function transferEvidenceOwnership(bytes32 _recordId, address _newOwner) public onlyOwner(_recordId) {
        require(_newOwner != address(0), "New owner address cannot be zero");
        require(_newOwner != evidenceRecords[_recordId].owner, "New owner must be different");

        // Update ownership
        evidenceRecords[_recordId].owner = _newOwner;

        // Add custody log entry for transfer
        evidenceRecords[_recordId].custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "Ownership transferred to new owner",
            timestamp: block.timestamp
        }));

        // Update ownerEvidence mappings
        bytes32[] storage ownerRecords = ownerEvidence[msg.sender];
        for (uint256 i = 0; i < ownerRecords.length; i++) {
            if (ownerRecords[i] == _recordId) {
                ownerRecords[i] = ownerRecords[ownerRecords.length - 1];
                ownerRecords.pop();
                break;
            }
        }
        ownerEvidence[_newOwner].push(_recordId);

        // Emit events for ownership transfer and custody update
        emit EvidenceTransferred(_recordId, _newOwner);
        emit CustodyUpdated(_recordId, msg.sender, "Ownership transferred to new owner");
    }

    /**
     * @dev Authorizes a verifier to access an evidence record.
     * @param _recordId The ID of the evidence record.
     * @param _verifier The address of the verifier to authorize.
     */
    function authorizeVerifier(bytes32 _recordId, address _verifier) public onlyOwner(_recordId) {
        require(_verifier != address(0), "Verifier address cannot be zero");
        // Check if verifier is already authorized
        for (uint256 i = 0; i < evidenceRecords[_recordId].authorizedVerifiers.length; i++) {
            require(evidenceRecords[_recordId].authorizedVerifiers[i] != _verifier, "Verifier already authorized");
        }
        evidenceRecords[_recordId].authorizedVerifiers.push(_verifier);

        // Add custody log entry for authorization
        evidenceRecords[_recordId].custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "Verifier authorized",
            timestamp: block.timestamp
        }));

        // Emit events for verifier authorization and custody update
        emit VerifierAuthorized(_recordId, _verifier);
        emit CustodyUpdated(_recordId, msg.sender, "Verifier authorized");
    }

    /**
     * @dev Verifies an evidence record against provided data and optional signature.
     * @param _recordId The ID of the evidence record.
     * @param _data The data to verify against the stored hash and signature.
     * @return isValid True if the data and signature (if provided) are valid, false otherwise.
     * @return recoveredSigner The address recovered from the signature (or zero if no signature).
     */
    function verifyEvidence(bytes32 _recordId, bytes memory _data) public onlyAuthorized(_recordId) returns (bool isValid, address recoveredSigner) {
        require(evidenceRecords[_recordId].exists, "Evidence record does not exist");
        require(_data.length > 0, "Data cannot be empty");

        // Verify data hash
        bytes32 computedHash = keccak256(_data);
        bool hashValid = (computedHash == evidenceRecords[_recordId].dataHash);

        // Initialize signature verification results
        bool signatureValid = true;
        recoveredSigner = address(0);

        // Verify signature if provided in the record
        if (evidenceRecords[_recordId].signature.length == 65) {
            bytes memory signature = evidenceRecords[_recordId].signature;
            bytes32 messageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", computedHash));

            // Extract signature components (r, s, v)
            bytes32 r;
            bytes32 s;
            uint8 v;
            assembly {
                r := mload(add(signature, 32))
                s := mload(add(signature, 64))
                v := byte(0, mload(add(signature, 65)))
            }

            // Adjust v if necessary (27 or 28 for Ethereum signatures)
            if (v < 27) {
                v += 27;
            }
            require(v == 27 || v == 28, "Invalid signature v value");

            // Recover the signer address
            recoveredSigner = ecrecover(messageHash, v, r, s);
            signatureValid = (recoveredSigner != address(0) && recoveredSigner == evidenceRecords[_recordId].owner);
        }

        // Overall validity requires both hash and signature (if present) to be valid
        isValid = hashValid && signatureValid;

        // Emit event for evidence verification
        emit EvidenceVerified(_recordId, msg.sender, isValid);

        return (isValid, recoveredSigner);
    }

    /**
     * @dev Retrieves the details of an evidence record.
     * @param _recordId The ID of the evidence record.
     * @return dataHash The stored data hash.
     * @return description The description of the evidence.
     * @return signature The stored signature (if any).
     * @return owner The owner of the evidence record.
     * @return timestamp The timestamp of evidence creation.
     */
    function getEvidence(bytes32 _recordId)
        public
        view
        onlyAuthorized(_recordId)
        returns (
            bytes32 dataHash,
            string memory description,
            bytes memory signature,
            address owner,
            uint256 timestamp
        )
    {
        require(evidenceRecords[_recordId].exists, "Evidence record does not exist");
        EvidenceRecord storage record = evidenceRecords[_recordId];
        return (
            record.dataHash,
            record.description,
            record.signature,
            record.owner,
            record.timestamp
        );
    }

    /**
     * @dev Retrieves the list of authorized verifiers for an evidence record.
     * @param _recordId The ID of the evidence record.
     * @return The array of authorized verifier addresses.
     */
    function getAuthorizedVerifiers(bytes32 _recordId)
        public
        view
        onlyOwner(_recordId)
        returns (address[] memory)
    {
        return evidenceRecords[_recordId].authorizedVerifiers;
    }

    /**
     * @dev Retrieves the chain-of-custody log for an evidence record.
     * @param _recordId The ID of the evidence record.
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
        require(evidenceRecords[_recordId].exists, "Evidence record does not exist");
        EvidenceRecord storage record = evidenceRecords[_recordId];
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
     * @dev Retrieves the list of evidence record IDs for a given owner.
     * @param _owner The address of the owner.
     * @return The array of evidence record IDs.
     */
    function getOwnerEvidence(address _owner) public view returns (bytes32[] memory) {
        return ownerEvidence[_owner];
    }
}