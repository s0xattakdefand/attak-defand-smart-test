// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

/**
 * @title DoDIntelligenceMissionArea
 * @dev A smart contract for managing DoD Intelligence Mission Area records.
 * Supports secure storage, access control, and dissemination of intelligence mission data.
 * THIS IS AN EXAMPLE CONTRACT THAT USES UN-AUDITED CODE.
 * DO NOT USE THIS CODE IN PRODUCTION.
 */
contract DoDIntelligenceMissionArea {
    // Enum to represent intelligence types
    enum IntelligenceType { HUMINT, SIGINT, GEOINT, MASINT, OSINT }

    // Struct to represent an Intelligence Mission record
    struct MissionRecord {
        string missionName; // Name of the mission (e.g., "Operation Alpha")
        string description; // Description of the mission
        IntelligenceType intelType; // Type of intelligence (e.g., HUMINT, SIGINT)
        string classification; // Classification level (e.g., "Unclassified", "Secret")
        mapping(string => string) requirements; // Intelligence requirements (e.g., "TargetData" => "Location")
        string[] requirementKeys; // Array to track requirement keys
        address owner; // Owner of the record (e.g., DIA officer)
        address[] authorizedAnalysts; // List of authorized analysts
        bool isDisseminable; // Indicates if cleared for dissemination
        bool exists; // Flag to check if record exists
    }

    // Mapping to store mission records by their unique ID
    mapping(bytes32 => MissionRecord) public missionRecords;

    // Event emitted when a new mission record is created
    event MissionRecordCreated(bytes32 indexed recordId, string missionName, address indexed owner);
    // Event emitted when a mission record is updated
    event MissionRecordUpdated(bytes32 indexed recordId, string missionName, address indexed owner);
    // Event emitted when a requirement is added
    event RequirementAdded(bytes32 indexed recordId, string requirementKey, string requirementValue);
    // Event emitted when an analyst is authorized
    event AnalystAuthorized(bytes32 indexed recordId, address indexed analyst);
    // Event emitted when dissemination status is updated
    event DisseminationStatusUpdated(bytes32 indexed recordId, bool isDisseminable);

    // Modifier to check if the caller is the owner of the mission record
    modifier onlyRecordOwner(bytes32 recordId) {
        require(missionRecords[recordId].owner == msg.sender, "Only the record owner can perform this action");
        require(missionRecords[recordId].exists, "Mission record does not exist");
        _;
    }

    // Modifier to check if the caller is an authorized analyst
    modifier onlyAuthorizedAnalyst(bytes32 recordId) {
        require(missionRecords[recordId].exists, "Mission record does not exist");
        bool isAuthorized = missionRecords[recordId].owner == msg.sender;
        if (!isAuthorized) {
            for (uint256 i = 0; i < missionRecords[recordId].authorizedAnalysts.length; i++) {
                if (missionRecords[recordId].authorizedAnalysts[i] == msg.sender) {
                    isAuthorized = true;
                    break;
                }
            }
        }
        require(isAuthorized, "Only authorized analysts can perform this action");
        _;
    }

    /**
     * @dev Creates a new Intelligence Mission record.
     * @param _missionName The name of the mission.
     * @param _description The description of the mission.
     * @param _intelType The type of intelligence (e.g., HUMINT, SIGINT).
     * @param _classification The classification level (e.g., "Secret").
     * @param _isDisseminable Whether the mission data is cleared for dissemination.
     * @return recordId The unique ID of the created record.
     */
    function createMissionRecord(
        string memory _missionName,
        string memory _description,
        IntelligenceType _intelType,
        string memory _classification,
        bool _isDisseminable
    ) public returns (bytes32) {
        // Generate a unique ID for the mission record
        bytes32 recordId = keccak256(abi.encodePacked(_missionName, msg.sender, block.timestamp));
        
        // Ensure the record doesn't already exist
        require(!missionRecords[recordId].exists, "Mission record with this ID already exists");

        // Initialize the mission record
        MissionRecord storage newRecord = missionRecords[recordId];
        newRecord.missionName = _missionName;
        newRecord.description = _description;
        newRecord.intelType = _intelType;
        newRecord.classification = _classification;
        newRecord.isDisseminable = _isDisseminable;
        newRecord.owner = msg.sender;
        newRecord.exists = true;
        newRecord.authorizedAnalysts.push(msg.sender); // Owner is an initial analyst

        // Emit event for mission record creation
        emit MissionRecordCreated(recordId, _missionName, msg.sender);

        return recordId;
    }

    /**
     * @dev Updates the core fields of an existing mission record.
     * @param _recordId The ID of the mission record to update.
     * @param _description The new description.
     * @param _classification The new classification level.
     */
    function updateMissionRecord(
        bytes32 _recordId,
        string memory _description,
        string memory _classification
    ) public onlyRecordOwner(_recordId) {
        MissionRecord storage record = missionRecords[_recordId];
        record.description = _description;
        record.classification = _classification;

        // Emit event for mission record update
        emit MissionRecordUpdated(_recordId, record.missionName, msg.sender);
    }

    /**
     * @dev Adds an intelligence requirement to a mission record.
     * @param _recordId The ID of the mission record.
     * @param _requirementKey The key of the requirement (e.g., "TargetData").
     * @param _requirementValue The value of the requirement (e.g., "Location").
     */
    function addRequirement(
        bytes32 _recordId,
        string memory _requirementKey,
        string memory _requirementValue
    ) public onlyRecordOwner(_recordId) {
        missionRecords[_recordId].requirements[_requirementKey] = _requirementValue;
        missionRecords[_recordId].requirementKeys.push(_requirementKey);

        // Emit event for requirement addition
        emit RequirementAdded(_recordId, _requirementKey, _requirementValue);
    }

    /**
     * @dev Adds an authorized analyst to a mission record.
     * @param _recordId The ID of the mission record.
     * @param _analyst The address of the analyst to authorize.
     */
    function authorizeAnalyst(bytes32 _recordId, address _analyst) public onlyRecordOwner(_recordId) {
        require(_analyst != address(0), "Invalid analyst address");
        // Check if analyst is already authorized
        for (uint256 i = 0; i < missionRecords[_recordId].authorizedAnalysts.length; i++) {
            require(missionRecords[_recordId].authorizedAnalysts[i] != _analyst, "Analyst already authorized");
        }
        missionRecords[_recordId].authorizedAnalysts.push(_analyst);

        // Emit event for analyst authorization
        emit AnalystAuthorized(_recordId, _analyst);
    }

    /**
     * @dev Updates the dissemination status of a mission record.
     * @param _recordId The ID of the mission record.
     * @param _isDisseminable The new dissemination status.
     */
    function updateDisseminationStatus(bytes32 _recordId, bool _isDisseminable) public onlyRecordOwner(_recordId) {
        missionRecords[_recordId].isDisseminable = _isDisseminable;

        // Emit event for dissemination status update
        emit DisseminationStatusUpdated(_recordId, _isDisseminable);
    }

    /**
     * @dev Retrieves the core fields of a mission record.
     * @param _recordId The ID of the mission record.
     * @return missionName The name of the mission.
     * @return description The description of the mission.
     * @return intelType The type of intelligence.
     * @return classification The classification level.
     * @return isDisseminable The dissemination status.
     * @return owner The owner of the record.
     */
    function getMissionRecord(bytes32 _recordId)
        public
        view
        onlyAuthorizedAnalyst(_recordId)
        returns (
            string memory missionName,
            string memory description,
            IntelligenceType intelType,
            string memory classification,
            bool isDisseminable,
            address owner
        )
    {
        require(missionRecords[_recordId].exists, "Mission record does not exist");
        MissionRecord storage record = missionRecords[_recordId];
        return (
            record.missionName,
            record.description,
            record.intelType,
            record.classification,
            record.isDisseminable,
            record.owner
        );
    }

    /**
     * @dev Retrieves the value of an intelligence requirement.
     * @param _recordId The ID of the mission record.
     * @param _requirementKey The key of the requirement.
     * @return The value of the requirement.
     */
    function getRequirement(bytes32 _recordId, string memory _requirementKey)
        public
        view
        onlyAuthorizedAnalyst(_recordId)
        returns (string memory)
    {
        require(missionRecords[_recordId].exists, "Mission record does not exist");
        return missionRecords[_recordId].requirements[_requirementKey];
    }

    /**
     * @dev Retrieves the list of requirement keys for a mission record.
     * @param _recordId The ID of the mission record.
     * @return The array of requirement keys.
     */
    function getRequirementKeys(bytes32 _recordId)
        public
        view
        onlyAuthorizedAnalyst(_recordId)
        returns (string[] memory)
    {
        require(missionRecords[_recordId].exists, "Mission record does not exist");
        return missionRecords[_recordId].requirementKeys;
    }

    /**
     * @dev Retrieves the list of authorized analysts for a mission record.
     * @param _recordId The ID of the mission record.
     * @return The array of authorized analyst addresses.
     */
    function getAuthorizedAnalysts(bytes32 _recordId)
        public
        view
        onlyRecordOwner(_recordId)
        returns (address[] memory)
    {
        require(missionRecords[_recordId].exists, "Mission record does not exist");
        return missionRecords[_recordId].authorizedAnalysts;
    }

    /**
     * @dev Retrieves publicly disseminable mission details.
     * @param _recordId The ID of the mission record.
     * @return missionName The name of the mission.
     * @return description The description of the mission.
     */
    function getPublicMissionDetails(bytes32 _recordId)
        public
        view
        returns (string memory missionName, string memory description)
    {
        require(missionRecords[_recordId].exists, "Mission record does not exist");
        require(missionRecords[_recordId].isDisseminable, "Mission data is not disseminable");
        MissionRecord storage record = missionRecords[_recordId];
        return (record.missionName, record.description);
    }
}