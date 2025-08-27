// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

/**
 * @title DoDIACAP
 * @dev A smart contract for managing the DoD Information Assurance Certification and Accreditation Process (DIACAP).
 * Supports creation, management, and accreditation of information system C&A records.
 * THIS IS AN EXAMPLE CONTRACT THAT USES UN-AUDITED CODE.
 * DO NOT USE THIS CODE IN PRODUCTION.
 */
contract DoDIACAP {
    // Struct to represent a DIACAP Certification and Accreditation record
    struct CARecord {
        string systemName; // Name of the information system (e.g., "Mission System X")
        string description; // Description of the system and C&A scope
        string missionAssuranceCategory; // Mission Assurance Category (MAC I, II, or III)
        string confidentialityLevel; // Confidentiality Level (e.g., Public, Sensitive, Classified)
        mapping(string => bool) securityControls; // IA controls (e.g., "ECAN-1" => compliant)
        string[] controlKeys; // Array to track defined control keys
        address owner; // Owner of the record (e.g., system owner)
        address certifyingAuthority; // Certifying Authority (CA) for the system
        bool isAccredited; // Accreditation status (ATO granted or not)
        string accreditationDecision; // Accreditation decision details (e.g., "ATO", "IATO")
        bool exists; // Flag to check if record exists
    }

    // Mapping to store C&A records by their unique ID
    mapping(bytes32 => CARecord) public caRecords;

    // Event emitted when a new C&A record is created
    event CARecordCreated(bytes32 indexed recordId, string systemName, address indexed owner);
    // Event emitted when a C&A record is updated
    event CARecordUpdated(bytes32 indexed recordId, string systemName, address indexed owner);
    // Event emitted when a security control is added
    event SecurityControlAdded(bytes32 indexed recordId, string controlKey, bool compliant);
    // Event emitted when a security control's compliance status is updated
    event SecurityControlStatusUpdated(bytes32 indexed recordId, string controlKey, bool compliant);
    // Event emitted when an accreditation decision is made
    event AccreditationDecisionMade(bytes32 indexed recordId, string accreditationDecision);

    // Modifier to check if the caller is the owner of the C&A record
    modifier onlyRecordOwner(bytes32 recordId) {
        require(caRecords[recordId].owner == msg.sender, "Only the record owner can perform this action");
        require(caRecords[recordId].exists, "C&A record does not exist");
        _;
    }

    // Modifier to check if the caller is the Certifying Authority
    modifier onlyCertifyingAuthority(bytes32 recordId) {
        require(caRecords[recordId].certifyingAuthority == msg.sender, "Only the Certifying Authority can perform this action");
        require(caRecords[recordId].exists, "C&A record does not exist");
        _;
    }

    /**
     * @dev Creates a new DIACAP C&A record.
     * @param _systemName The name of the information system.
     * @param _description The description of the system and C&A scope.
     * @param _missionAssuranceCategory The Mission Assurance Category (MAC I, II, or III).
     * @param _confidentialityLevel The Confidentiality Level (e.g., Public, Sensitive, Classified).
     * @param _certifyingAuthority The address of the Certifying Authority.
     * @return recordId The unique ID of the created C&A record.
     */
    function createCARecord(
        string memory _systemName,
        string memory _description,
        string memory _missionAssuranceCategory,
        string memory _confidentialityLevel,
        address _certifyingAuthority
    ) public returns (bytes32) {
        require(_certifyingAuthority != address(0), "Invalid Certifying Authority address");
        // Generate a unique ID for the C&A record
        bytes32 recordId = keccak256(abi.encodePacked(_systemName, msg.sender, block.timestamp));
        
        // Ensure the record doesn't already exist
        require(!caRecords[recordId].exists, "C&A record with this ID already exists");

        // Initialize the C&A record
        CARecord storage newRecord = caRecords[recordId];
        newRecord.systemName = _systemName;
        newRecord.description = _description;
        newRecord.missionAssuranceCategory = _missionAssuranceCategory;
        newRecord.confidentialityLevel = _confidentialityLevel;
        newRecord.owner = msg.sender;
        newRecord.certifyingAuthority = _certifyingAuthority;
        newRecord.isAccredited = false;
        newRecord.accreditationDecision = "Pending";
        newRecord.exists = true;

        // Emit event for C&A record creation
        emit CARecordCreated(recordId, _systemName, msg.sender);

        return recordId;
    }

    /**
     * @dev Updates the core fields of an existing C&A record.
     * @param _recordId The ID of the C&A record to update.
     * @param _description The new description.
     * @param _missionAssuranceCategory The new Mission Assurance Category.
     * @param _confidentialityLevel The new Confidentiality Level.
     */
    function updateCARecord(
        bytes32 _recordId,
        string memory _description,
        string memory _missionAssuranceCategory,
        string memory _confidentialityLevel
    ) public onlyRecordOwner(_recordId) {
        CARecord storage record = caRecords[_recordId];
        record.description = _description;
        record.missionAssuranceCategory = _missionAssuranceCategory;
        record.confidentialityLevel = _confidentialityLevel;

        // Emit event for C&A record update
        emit CARecordUpdated(_recordId, record.systemName, msg.sender);
    }

    /**
     * @dev Adds a security control to a C&A record.
     * @param _recordId The ID of the C&A record.
     * @param _controlKey The key of the security control (e.g., "ECAN-1").
     * @param _compliant Whether the control is compliant.
     */
    function addSecurityControl(
        bytes32 _recordId,
        string memory _controlKey,
        bool _compliant
    ) public onlyRecordOwner(_recordId) {
        caRecords[_recordId].securityControls[_controlKey] = _compliant;
        caRecords[_recordId].controlKeys.push(_controlKey);

        // Emit event for security control addition
        emit SecurityControlAdded(_recordId, _controlKey, _compliant);
    }

    /**
     * @dev Updates the compliance status of a security control.
     * @param _recordId The ID of the C&A record.
     * @param _controlKey The key of the security control.
     * @param _compliant The new compliance status.
     */
    function updateSecurityControlStatus(
        bytes32 _recordId,
        string memory _controlKey,
        bool _compliant
    ) public onlyRecordOwner(_recordId) {
        // Check if the control exists
        bool controlExists = false;
        for (uint256 i = 0; i < caRecords[_recordId].controlKeys.length; i++) {
            if (keccak256(abi.encodePacked(caRecords[_recordId].controlKeys[i])) == keccak256(abi.encodePacked(_controlKey))) {
                controlExists = true;
                break;
            }
        }
        require(controlExists, "Security control does not exist");

        caRecords[_recordId].securityControls[_controlKey] = _compliant;

        // Emit event for security control status update
        emit SecurityControlStatusUpdated(_recordId, _controlKey, _compliant);
    }

    /**
     * @dev Issues an accreditation decision for a C&A record.
     * @param _recordId The ID of the C&A record.
     * @param _decision The accreditation decision (e.g., "ATO", "IATO", "Denied").
     */
    function makeAccreditationDecision(
        bytes32 _recordId,
        string memory _decision
    ) public onlyCertifyingAuthority(_recordId) {
        CARecord storage record = caRecords[_recordId];
        record.accreditationDecision = _decision;
        record.isAccredited = (keccak256(abi.encodePacked(_decision)) == keccak256(abi.encodePacked("ATO")) ||
                              keccak256(abi.encodePacked(_decision)) == keccak256(abi.encodePacked("IATO")));

        // Emit event for accreditation decision
        emit AccreditationDecisionMade(_recordId, _decision);
    }

    /**
     * @dev Checks if all security controls for a C&A record are compliant.
     * @param _recordId The ID of the C&A record.
     * @return Whether all security controls are compliant.
     */
    function isSystemCompliant(bytes32 _recordId) public view returns (bool) {
        require(caRecords[_recordId].exists, "C&A record does not exist");
        // Check each control in the controlKeys array
        for (uint256 i = 0; i < caRecords[_recordId].controlKeys.length; i++) {
            string memory key = caRecords[_recordId].controlKeys[i];
            if (!caRecords[_recordId].securityControls[key]) {
                return false;
            }
        }
        return true;
    }

    /**
     * @dev Retrieves the core fields of a C&A record.
     * @param _recordId The ID of the C&A record.
     * @return systemName The name of the system.
     * @return description The description of the system.
     * @return missionAssuranceCategory The Mission Assurance Category.
     * @return confidentialityLevel The Confidentiality Level.
     * @return owner The owner of the record.
     * @return certifyingAuthority The Certifying Authority.
     * @return isAccredited The accreditation status.
     * @return accreditationDecision The accreditation decision.
     */
    function getCARecord(bytes32 _recordId)
        public
        view
        returns (
            string memory systemName,
            string memory description,
            string memory missionAssuranceCategory,
            string memory confidentialityLevel,
            address owner,
            address certifyingAuthority,
            bool isAccredited,
            string memory accreditationDecision
        )
    {
        require(caRecords[_recordId].exists, "C&A record does not exist");
        CARecord storage record = caRecords[_recordId];
        return (
            record.systemName,
            record.description,
            record.missionAssuranceCategory,
            record.confidentialityLevel,
            record.owner,
            record.certifyingAuthority,
            record.isAccredited,
            record.accreditationDecision
        );
    }

    /**
     * @dev Retrieves the compliance status of a security control.
     * @param _recordId The ID of the C&A record.
     * @param _controlKey The key of the security control.
     * @return The compliance status of the control.
     */
    function getSecurityControlStatus(bytes32 _recordId, string memory _controlKey)
        public
        view
        returns (bool)
    {
        require(caRecords[_recordId].exists, "C&A record does not exist");
        return caRecords[_recordId].securityControls[_controlKey];
    }

    /**
     * @dev Retrieves the list of security control keys for a C&A record.
     * @param _recordId The ID of the C&A record.
     * @return The array of control keys.
     */
    function getControlKeys(bytes32 _recordId)
        public
        view
        returns (string[] memory)
    {
        require(caRecords[_recordId].exists, "C&A record does not exist");
        return caRecords[_recordId].controlKeys;
    }
}
