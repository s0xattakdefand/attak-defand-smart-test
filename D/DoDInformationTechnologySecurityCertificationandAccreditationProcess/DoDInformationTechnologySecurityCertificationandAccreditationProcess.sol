// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

/**
 * @title DoDITSCAP
 * @dev A smart contract for managing the DoD Information Technology Security Certification and Accreditation Process (DITSCAP).
 * Supports creation, management, and accreditation of information system C&A records.
 * THIS IS AN EXAMPLE CONTRACT THAT USES UN-AUDITED CODE.
 * DO NOT USE THIS CODE IN PRODUCTION.
 */
contract DoDITSCAP {
    // Enum to represent DITSCAP phases
    enum Phase { Definition, Verification, Validation, PostAccreditation }

    // Struct to represent a DITSCAP Certification and Accreditation record
    struct CARecord {
        string systemName; // Name of the information system (e.g., "Navy Intranet")
        string description; // Description of the system and C&A scope
        string securityLevel; // Security level (e.g., "Low", "Medium", "High")
        Phase currentPhase; // Current DITSCAP phase
        mapping(string => bool) securityControls; // Security controls (e.g., "IA-1" => compliant)
        string[] controlKeys; // Array to track defined control keys
        address owner; // Owner of the record (e.g., system owner)
        address certifyingAuthority; // Certifying Authority (CA) for the system
        bool isAccredited; // Accreditation status (ATO granted or not)
        string accreditationDecision; // Accreditation decision details (e.g., "ATO", "Denied")
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
    // Event emitted when the DITSCAP phase is updated
    event PhaseUpdated(bytes32 indexed recordId, Phase newPhase);
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
     * @dev Creates a new DITSCAP C&A record.
     * @param _systemName The name of the information system.
     * @param _description The description of the system and C&A scope.
     * @param _securityLevel The security level (e.g., "Low", "Medium", "High").
     * @param _certifyingAuthority The address of the Certifying Authority.
     * @return recordId The unique ID of the created C&A record.
     */
    function createCARecord(
        string memory _systemName,
        string memory _description,
        string memory _securityLevel,
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
        newRecord.securityLevel = _securityLevel;
        newRecord.currentPhase = Phase.Definition;
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
     * @param _securityLevel The new security level.
     */
    function updateCARecord(
        bytes32 _recordId,
        string memory _description,
        string memory _securityLevel
    ) public onlyRecordOwner(_recordId) {
        CARecord storage record = caRecords[_recordId];
        record.description = _description;
        record.securityLevel = _securityLevel;

        // Emit event for C&A record update
        emit CARecordUpdated(_recordId, record.systemName, msg.sender);
    }

    /**
     * @dev Adds a security control to a C&A record.
     * @param _recordId The ID of the C&A record.
     * @param _controlKey The key of the security control (e.g., "IA-1").
     * @param _compliant Whether the control is compliant.
     */
    function addSecurityControl(
        bytes32 _recordId,
        string memory _controlKey,
        bool _compliant
    ) public onlyRecordOwner(_recordId) {
        require(caRecords[_recordId].currentPhase == Phase.Definition, "Can only add controls in Definition phase");
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
        require(caRecords[_recordId].currentPhase == Phase.Verification || caRecords[_recordId].currentPhase == Phase.Validation, 
                "Can only update controls in Verification or Validation phase");
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
     * @dev Advances the DITSCAP phase of a C&A record.
     * @param _recordId The ID of the C&A record.
     * @param _newPhase The new phase to advance to.
     */
    function advancePhase(bytes32 _recordId, Phase _newPhase) public onlyCertifyingAuthority(_recordId) {
        require(uint256(_newPhase) > uint256(caRecords[_recordId].currentPhase), "Can only advance to a later phase");
        caRecords[_recordId].currentPhase = _newPhase;

        // Emit event for phase update
        emit PhaseUpdated(_recordId, _newPhase);
    }

    /**
     * @dev Issues an accreditation decision for a C&A record.
     * @param _recordId The ID of the C&A record.
     * @param _decision The accreditation decision (e.g., "ATO", "Denied").
     */
    function makeAccreditationDecision(
        bytes32 _recordId,
        string memory _decision
    ) public onlyCertifyingAuthority(_recordId) {
        require(caRecords[_recordId].currentPhase == Phase.Validation, "Accreditation decision can only be made in Validation phase");
        CARecord storage record = caRecords[_recordId];
        record.accreditationDecision = _decision;
        record.isAccredited = (keccak256(abi.encodePacked(_decision)) == keccak256(abi.encodePacked("ATO")));

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
     * @return securityLevel The security level.
     * @return currentPhase The current DITSCAP phase.
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
            string memory securityLevel,
            Phase currentPhase,
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
            record.securityLevel,
            record.currentPhase,
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
