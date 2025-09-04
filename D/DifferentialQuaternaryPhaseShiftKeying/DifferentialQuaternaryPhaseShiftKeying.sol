// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

/**
 * @title DifferentialQuaternaryPhaseShiftKeying
 * @dev A smart contract for managing and tracking research on Differential Quaternary Phase Shift Keying (DQPSK).
 * Allows users to record DQPSK scenarios, parameters, and analysis with access control.
 * THIS IS AN EXAMPLE CONTRACT FOR EDUCATIONAL PURPOSES ONLY AND USES UN-AUDITED CODE.
 * DO NOT USE THIS CODE IN PRODUCTION.
 */
contract DifferentialQuaternaryPhaseShiftKeying {
    // Struct to represent a DQPSK research record
    struct DQPSKRecord {
        string scenarioName; // Name of the DQPSK scenario (e.g., "Wireless Communication Simulation")
        string description; // Description of the DQPSK scenario
        string modulationParameters; // Modulation parameters (e.g., "Symbol Rate: 1 Msps, Carrier Frequency: 2.4 GHz")
        mapping(string => string) analysisResults; // Analysis results (e.g., "BER" => "0.001")
        string[] analysisKeys; // Array to track analysis keys
        address researcher; // Researcher or owner of the record
        bool exists; // Flag to check if record exists
    }

    // Mapping to store DQPSK records by their unique ID
    mapping(bytes32 => DQPSKRecord) public dqpskRecords;

    // Event emitted when a new DQPSK record is created
    event DQPSKRecordCreated(bytes32 indexed recordId, string scenarioName, address indexed researcher);
    // Event emitted when a DQPSK record is updated
    event DQPSKRecordUpdated(bytes32 indexed recordId, string scenarioName, address indexed researcher);
    // Event emitted when an analysis result is added
    event AnalysisResultAdded(bytes32 indexed recordId, string analysisKey, string analysisValue);

    // Modifier to check if the caller is the researcher of the DQPSK record
    modifier onlyResearcher(bytes32 recordId) {
        require(dqpskRecords[recordId].researcher == msg.sender, "Only the researcher can perform this action");
        require(dqpskRecords[recordId].exists, "DQPSK record does not exist");
        _;
    }

    /**
     * @dev Creates a new DQPSK research record.
     * @param _scenarioName The name of the DQPSK scenario.
     * @param _description The description of the DQPSK scenario.
     * @param _modulationParameters The modulation parameters.
     * @return recordId The unique ID of the created DQPSK record.
     */
    function createDQPSKRecord(
        string memory _scenarioName,
        string memory _description,
        string memory _modulationParameters
    ) public returns (bytes32) {
        // Generate a unique ID for the DQPSK record
        bytes32 recordId = keccak256(abi.encodePacked(_scenarioName, msg.sender, block.timestamp));
        
        // Ensure the record doesn't already exist
        require(!dqpskRecords[recordId].exists, "DQPSK record with this ID already exists");

        // Initialize the DQPSK record
        DQPSKRecord storage newRecord = dqpskRecords[recordId];
        newRecord.scenarioName = _scenarioName;
        newRecord.description = _description;
        newRecord.modulationParameters = _modulationParameters;
        newRecord.researcher = msg.sender;
        newRecord.exists = true;

        // Emit event for DQPSK record creation
        emit DQPSKRecordCreated(recordId, _scenarioName, msg.sender);

        return recordId;
    }

    /**
     * @dev Updates the description of an existing DQPSK record.
     * @param _recordId The ID of the DQPSK record to update.
     * @param _newDescription The new description for the DQPSK record.
     */
    function updateDQPSKRecordDescription(bytes32 _recordId, string memory _newDescription) public onlyResearcher(_recordId) {
        dqpskRecords[_recordId].description = _newDescription;

        // Emit event for DQPSK record update
        emit DQPSKRecordUpdated(_recordId, dqpskRecords[_recordId].scenarioName, msg.sender);
    }

    /**
     * @dev Adds an analysis result to a DQPSK record.
     * @param _recordId The ID of the DQPSK record.
     * @param _analysisKey The key of the analysis (e.g., "BER").
     * @param _analysisValue The value or result of the analysis (e.g., "0.001").
     */
    function addAnalysisResult(bytes32 _recordId, string memory _analysisKey, string memory _analysisValue) public onlyResearcher(_recordId) {
        dqpskRecords[_recordId].analysisResults[_analysisKey] = _analysisValue;
        dqpskRecords[_recordId].analysisKeys.push(_analysisKey);

        // Emit event for analysis result addition
        emit AnalysisResultAdded(_recordId, _analysisKey, _analysisValue);
    }

    /**
     * @dev Retrieves the details of a DQPSK record.
     * @param _recordId The ID of the DQPSK record.
     * @return scenarioName The name of the DQPSK scenario.
     * @return description The description of the DQPSK scenario.
     * @return modulationParameters The modulation parameters.
     * @return researcher The researcher or owner of the record.
     */
    function getDQPSKRecord(bytes32 _recordId) public view returns (string memory scenarioName, string memory description, string memory modulationParameters, address researcher) {
        require(dqpskRecords[_recordId].exists, "DQPSK record does not exist");
        DQPSKRecord storage dqpsk = dqpskRecords[_recordId];
        return (dqpsk.scenarioName, dqpsk.description, dqpsk.modulationParameters, dqpsk.researcher);
    }

    /**
     * @dev Retrieves the value of a specific analysis result in a DQPSK record.
     * @param _recordId The ID of the DQPSK record.
     * @param _analysisKey The key of the analysis.
     * @return The value of the analysis result.
     */
    function getAnalysisResult(bytes32 _recordId, string memory _analysisKey) public view returns (string memory) {
        require(dqpskRecords[_recordId].exists, "DQPSK record does not exist");
        return dqpskRecords[_recordId].analysisResults[_analysisKey];
    }

    /**
     * @dev Retrieves the list of analysis keys in a DQPSK record.
     * @param _recordId The ID of the DQPSK record.
     * @return The array of analysis keys.
     */
    function getAnalysisKeys(bytes32 _recordId) public view returns (string[] memory) {
        require(dqpskRecords[_recordId].exists, "DQPSK record does not exist");
        return dqpskRecords[_recordId].analysisKeys;
    }
}
