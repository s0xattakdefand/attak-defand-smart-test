// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

/**
 * @title DifferentialFaultAttack
 * @dev A smart contract for managing and tracking research on Differential Fault Attacks (DFA).
 * Allows users to record DFA scenarios, mitigations, and analysis with access control.
 * THIS IS AN EXAMPLE CONTRACT FOR EDUCATIONAL PURPOSES ONLY AND USES UN-AUDITED CODE.
 * DO NOT USE THIS CODE IN PRODUCTION OR FOR ACTUAL ATTACKS.
 */
contract DifferentialFaultAttack {
    // Struct to represent a DFA research record
    struct DFARecord {
        string scenarioName; // Name of the DFA scenario (e.g., "AES Fault Injection")
        string description; // Description of the DFA scenario
        string targetAlgorithm; // Target cryptographic algorithm (e.g., "AES", "RSA")
        mapping(string => string) mitigations; // Mitigations (e.g., "Redundancy" => "Duplicate computations")
        string[] mitigationKeys; // Array to track mitigation keys
        address researcher; // Researcher or owner of the record
        bool exists; // Flag to check if record exists
    }

    // Mapping to store DFA records by their unique ID
    mapping(bytes32 => DFARecord) public dfaRecords;

    // Event emitted when a new DFA record is created
    event DFARecordCreated(bytes32 indexed recordId, string scenarioName, address indexed researcher);
    // Event emitted when a DFA record is updated
    event DFARecordUpdated(bytes32 indexed recordId, string scenarioName, address indexed researcher);
    // Event emitted when a mitigation is added
    event MitigationAdded(bytes32 indexed recordId, string mitigationKey, string mitigationValue);

    // Modifier to check if the caller is the researcher of the DFA record
    modifier onlyResearcher(bytes32 recordId) {
        require(dfaRecords[recordId].researcher == msg.sender, "Only the researcher can perform this action");
        require(dfaRecords[recordId].exists, "DFA record does not exist");
        _;
    }

    /**
     * @dev Creates a new DFA research record.
     * @param _scenarioName The name of the DFA scenario.
     * @param _description The description of the DFA scenario.
     * @param _targetAlgorithm The target cryptographic algorithm.
     * @return recordId The unique ID of the created DFA record.
     */
    function createDFARecord(
        string memory _scenarioName,
        string memory _description,
        string memory _targetAlgorithm
    ) public returns (bytes32) {
        // Generate a unique ID for the DFA record
        bytes32 recordId = keccak256(abi.encodePacked(_scenarioName, msg.sender, block.timestamp));
        
        // Ensure the record doesn't already exist
        require(!dfaRecords[recordId].exists, "DFA record with this ID already exists");

        // Initialize the DFA record
        DFARecord storage newRecord = dfaRecords[recordId];
        newRecord.scenarioName = _scenarioName;
        newRecord.description = _description;
        newRecord.targetAlgorithm = _targetAlgorithm;
        newRecord.researcher = msg.sender;
        newRecord.exists = true;

        // Emit event for DFA record creation
        emit DFARecordCreated(recordId, _scenarioName, msg.sender);

        return recordId;
    }

    /**
     * @dev Updates the description of an existing DFA record.
     * @param _recordId The ID of the DFA record to update.
     * @param _newDescription The new description for the DFA record.
     */
    function updateDFARecordDescription(bytes32 _recordId, string memory _newDescription) public onlyResearcher(_recordId) {
        dfaRecords[_recordId].description = _newDescription;

        // Emit event for DFA record update
        emit DFARecordUpdated(_recordId, dfaRecords[_recordId].scenarioName, msg.sender);
    }

    /**
     * @dev Adds a mitigation to a DFA record.
     * @param _recordId The ID of the DFA record.
     * @param _mitigationKey The key of the mitigation (e.g., "Redundancy").
     * @param _mitigationValue The value or description of the mitigation (e.g., "Duplicate computations").
     */
    function addMitigation(bytes32 _recordId, string memory _mitigationKey, string memory _mitigationValue) public onlyResearcher(_recordId) {
        dfaRecords[_recordId].mitigations[_mitigationKey] = _mitigationValue;
        dfaRecords[_recordId].mitigationKeys.push(_mitigationKey);

        // Emit event for mitigation addition
        emit MitigationAdded(_recordId, _mitigationKey, _mitigationValue);
    }

    /**
     * @dev Retrieves the details of a DFA record.
     * @param _recordId The ID of the DFA record.
     * @return scenarioName The name of the DFA scenario.
     * @return description The description of the DFA scenario.
     * @return targetAlgorithm The target cryptographic algorithm.
     * @return researcher The researcher or owner of the record.
     */
    function getDFARecord(bytes32 _recordId) public view returns (string memory scenarioName, string memory description, string memory targetAlgorithm, address researcher) {
        require(dfaRecords[_recordId].exists, "DFA record does not exist");
        DFARecord storage dfa = dfaRecords[_recordId];
        return (dfa.scenarioName, dfa.description, dfa.targetAlgorithm, dfa.researcher);
    }

    /**
     * @dev Retrieves the value of a specific mitigation in a DFA record.
     * @param _recordId The ID of the DFA record.
     * @param _mitigationKey The key of the mitigation.
     * @return The value of the mitigation.
     */
    function getMitigation(bytes32 _recordId, string memory _mitigationKey) public view returns (string memory) {
        require(dfaRecords[_recordId].exists, "DFA record does not exist");
        return dfaRecords[_recordId].mitigations[_mitigationKey];
    }

    /**
     * @dev Retrieves the list of mitigation keys in a DFA record.
     * @param _recordId The ID of the DFA record.
     * @return The array of mitigation keys.
     */
    function getMitigationKeys(bytes32 _recordId) public view returns (string[] memory) {
        require(dfaRecords[_recordId].exists, "DFA record does not exist");
        return dfaRecords[_recordId].mitigationKeys;
    }
}
