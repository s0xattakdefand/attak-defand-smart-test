// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

/**
 * @title DigitalSignature
 * @dev A smart contract for managing digital signatures to ensure authenticity and integrity.
 * Supports signature creation, storage, and verification with access control.
 * THIS IS AN EXAMPLE CONTRACT FOR EDUCATIONAL PURPOSES ONLY AND USES UN-AUDITED CODE.
 * DO NOT USE THIS CODE IN PRODUCTION.
 */
contract DigitalSignature {
    // Struct to represent a digital signature record
    struct SignatureRecord {
        bytes32 dataHash; // Keccak-256 hash of the signed data
        string description; // Description of the data (e.g., "Contract agreement")
        bytes signature; // Digital signature (r, s, v components)
        address signer; // Signer of the data
        uint256 timestamp; // Timestamp of signature creation
        bool exists; // Flag to check if record exists
    }

    // Mapping to store signature records by their unique ID
    mapping(bytes32 => SignatureRecord) public signatureRecords;
    // Mapping to track signature records by signer
    mapping(address => bytes32[]) public signerRecords;

    // Event emitted when a new signature is created
    event SignatureCreated(bytes32 indexed recordId, bytes32 dataHash, address indexed signer, string description);
    // Event emitted when a signature is updated
    event SignatureUpdated(bytes32 indexed recordId, string newDescription);
    // Event emitted when a signature is verified
    event SignatureVerified(bytes32 indexed recordId, address recoveredSigner, bool isValid);

    // Modifier to check if the caller is the signer of the signature record
    modifier onlySigner(bytes32 recordId) {
        require(signatureRecords[recordId].signer == msg.sender, "Only the signer can perform this action");
        require(signatureRecords[recordId].exists, "Signature record does not exist");
        _;
    }

    /**
     * @dev Creates a new digital signature record.
     * @param _data The data to sign (e.g., document, message).
     * @param _signature The digital signature of the data (r, s, v components).
     * @param _description The description of the data.
     * @return recordId The unique ID of the signature record.
     */
    function createSignature(
        bytes memory _data,
        bytes memory _signature,
        string memory _description
    ) public returns (bytes32) {
        require(_data.length > 0, "Data cannot be empty");
        require(_signature.length == 65, "Invalid signature length");
        require(bytes(_description).length > 0, "Description cannot be empty");

        // Generate the Keccak-256 hash of the data
        bytes32 dataHash = keccak256(_data);
        // Generate a unique record ID
        bytes32 recordId = keccak256(abi.encodePacked(dataHash, msg.sender, block.timestamp));
        
        // Ensure the record doesn't already exist
        require(!signatureRecords[recordId].exists, "Signature record with this ID already exists");

        // Initialize the signature record
        SignatureRecord storage newRecord = signatureRecords[recordId];
        newRecord.dataHash = dataHash;
        newRecord.description = _description;
        newRecord.signature = _signature;
        newRecord.signer = msg.sender;
        newRecord.timestamp = block.timestamp;
        newRecord.exists = true;

        // Add record ID to signer's list
        signerRecords[msg.sender].push(recordId);

        // Emit event for signature creation
        emit SignatureCreated(recordId, dataHash, msg.sender, _description);

        return recordId;
    }

    /**
     * @dev Updates the description of an existing signature record.
     * @param _recordId The ID of the signature record.
     * @param _newDescription The new description for the signature record.
     */
    function updateSignatureDescription(bytes32 _recordId, string memory _newDescription) public onlySigner(_recordId) {
        require(bytes(_newDescription).length > 0, "Description cannot be empty");
        signatureRecords[_recordId].description = _newDescription;

        // Emit event for signature update
        emit SignatureUpdated(_recordId, _newDescription);
    }

    /**
     * @dev Verifies a signature against provided data.
     * @param _recordId The ID of the signature record.
     * @param _data The data to verify against the stored signature.
     * @return isValid True if the signature is valid, false otherwise.
     * @return recoveredSigner The address recovered from the signature.
     */
    function verifySignature(bytes32 _recordId, bytes memory _data) public returns (bool isValid, address recoveredSigner) {
        require(signatureRecords[_recordId].exists, "Signature record does not exist");
        require(_data.length > 0, "Data cannot be empty");

        // Compute the hash of the provided data
        bytes32 dataHash = keccak256(_data);
        bytes32 messageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", dataHash));

        // Extract signature components (r, s, v)
        bytes memory signature = signatureRecords[_recordId].signature;
        require(signature.length == 65, "Invalid signature length");

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
        isValid = (recoveredSigner == signatureRecords[_recordId].signer && dataHash == signatureRecords[_recordId].dataHash);

        // Emit event for signature verification
        emit SignatureVerified(_recordId, recoveredSigner, isValid);

        return (isValid, recoveredSigner);
    }

    /**
     * @dev Retrieves the details of a signature record.
     * @param _recordId The ID of the signature record.
     * @return dataHash The stored data hash.
     * @return description The description of the data.
     * @return signature The stored signature.
     * @return signer The signer of the data.
     * @return timestamp The timestamp of signature creation.
     */
    function getSignature(bytes32 _recordId)
        public
        view
        returns (
            bytes32 dataHash,
            string memory description,
            bytes memory signature,
            address signer,
            uint256 timestamp
        )
    {
        require(signatureRecords[_recordId].exists, "Signature record does not exist");
        SignatureRecord storage record = signatureRecords[_recordId];
        return (
            record.dataHash,
            record.description,
            record.signature,
            record.signer,
            record.timestamp
        );
    }

    /**
     * @dev Retrieves the list of signature record IDs for a given signer.
     * @param _signer The address of the signer.
     * @return The array of signature record IDs.
     */
    function getSignerRecords(address _signer) public view returns (bytes32[] memory) {
        return signerRecords[_signer];
    }
}