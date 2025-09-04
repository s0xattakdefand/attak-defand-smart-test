// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

/**
 * @title DifferentialPowerAnalysis
 * @dev A smart contract for managing and tracking research on Differential Power Analysis (DPA).
 * Allows users to record DPA scenarios, mitigations, and analysis with access control.
 * THIS IS AN EXAMPLE CONTRACT FOR EDUCATIONAL PURPOSES ONLY AND USES UN-AUDITED CODE.
 * DO NOT USE THIS CODE IN PRODUCTION OR FOR ACTUAL ATTACKS.
 */
contract DifferentialPowerAnalysis {
    // Struct to represent a DPA research record
    struct DPARecord {
        string scenarioName; // Name of the DPA scenario (e.g., "AES Power Trace Analysis")
        string description; // Description of the DPA scenario
        string targetAlgorithm; // Target cryptographic algorithm (e.g., "AES", "RSA")
        mapping(string => string) mitigations; // Mitigations (e.g., "Masking" => "Randomize intermediate values")
        string[] mitigationKeys; // Array to track mitigation keys
        address researcher; // Researcher or owner of the record
        bool exists; // Flag to check if record exists
    }

    // Mapping to store DPA records by their unique ID
    mapping(bytes32 => DPARecord) public dpaRecords;

    // Event emitted when a new DPA record is created
    event DPARecordCreated(bytes32 indexed recordId, string scenarioName, address indexed researcher);
    // Event emitted when a DPA record is updated
    event DPARecordUpdated(bytes32 indexed recordId, string scenarioName, address indexed researcher);
    // Event emitted when a mitigation is added
    event MitigationAdded(bytes32 indexed recordId, string mitigationKey, string mitigationValue);

    // Modifier to check if the caller is the researcher of the DPA record
    modifier onlyResearcher(bytes32 recordId) {
        require(dpaRecords[recordId].researcher == msg.sender, "Only the researcher can perform this action");
        require(dpaRecords[recordId].exists, "DPA record does not exist");
        _;
    }

    /**
     * @dev Creates a new DPA research record.
     * @param _scenarioName The name of the DPA scenario.
     * @param _description The description of the DPA scenario.
     * @param _targetAlgorithm The target cryptographic algorithm.
     * @return recordId The unique ID of the created DPA record.
     */
    function createDPARecord(
        string memory _scenarioName,
        string memory _description,
        string memory _targetAlgorithm
    ) public returns (bytes32) {
        // Generate a unique ID for the DPA record
        bytes32 recordId = keccak256(abi.encodePacked(_scenarioName, msg.sender, block.timestamp));
        
        // Ensure the record doesn't already exist
        require(!dpaRecords[recordId].exists, "DPA record with this ID already exists");

        // Initialize the DPA record
        DPARecord storage newRecord = dpaRecords[recordId];
        newRecord.scenarioName = _scenarioName;
        newRecord.description = _description;
        newRecord.targetAlgorithm = _targetAlgorithm;
        newRecord.researcher = msg.sender;
        newRecord.exists = true;

        // Emit event for DPA record creation
        emit DPARecordCreated(recordId, _scenarioName, msg.sender);

        return recordId;
    }

    /**
     * @dev Updates the description of an existing DPA record.
     * @param _recordId The ID of the DPA record to update.
     * @param _newDescription The new description for the DPA record.
     */
    function updateDPARecordDescription(bytes32 _recordId, string memory _newDescription) public onlyResearcher(_recordId) {
        dpaRecords[_recordId].description = _newDescription;

        // Emit event for DPA record update
        emit DPARecordUpdated(_recordId, dpaRecords[_recordId].scenarioName, msg.sender);
    }

    /**
     * @dev Adds a mitigation to a DPA record.
     * @param _recordId The ID of the DPA record.
     * @param _mitigationKey The key of the mitigation (e.g., "Masking").
     * @param _mitigationValue The value or description of the mitigation (e.g., "Randomize intermediate values").
     */
    function addMitigation(bytes32 _recordId, string memory _mitigationKey, string memory _mitigationValue) public onlyResearcher(_recordId) {
        dpaRecords[_recordId].mitigations[_mitigationKey] = _mitigationValue;
        dpaRecords[_recordId].mitigationKeys.push(_mitigationKey);

        // Emit event for mitigation addition
        emit MitigationAdded(_recordId, _mitigationKey, _mitigationValue);
    }

    /**
     * @dev Retrieves the details of a DPA record.
     * @param _recordId The ID of the DPA record.
     * @return scenarioName The name of the DPA scenario.
     * @return description The description of the DPA scenario.
     * @return targetAlgorithm The target cryptographic algorithm.
     * @return researcher The researcher or owner of the record.
     */
    function getDPARecord(bytes32 _recordId) public view returns (string memory scenarioName, string memory description, string memory targetAlgorithm, address researcher) {
        require(dpaRecords[_recordId].exists, "DPA record does not exist");
        DPARecord storage dpa = dpaRecords[_recordId];
        return (dpa.scenarioName, dpa.description, dpa.targetAlgorithm, dpa.researcher);
    }

    /**
     * @dev Retrieves the value of a specific mitigation in a DPA record.
     * @param _recordId The ID of the DPA record.
     * @param _mitigationKey The key of the mitigation.
     * @return The value of the mitigation.
     */
    function getMitigation(bytes32 _recordId, string memory _mitigationKey) public view returns (string memory) {
        require(dpaRecords[_recordId].exists, "DPA record does not exist");
        return dpaRecords[_recordId].mitigations[_mitigationKey];
    }

    /**
     * @dev Retrieves the list of mitigation keys in a DPA record.
     * @param _recordId The ID of the DPA record.
     * @return The array of mitigation keys.
     */
    function getMitigationKeys(bytes32 _recordId) public view returns (string[] memory) {
        require(dpaRecords[_recordId].exists, "DPA record does not exist");
        return dpaRecords[_recordId].mitigationKeys;
    }
}
