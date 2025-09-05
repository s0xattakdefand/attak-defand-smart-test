// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

/**
 * @title DODCAR
 * @dev A smart contract for managing Department of Defense Cybersecurity Analysis and Review (DODCAR) records.
 * Supports tracking cybersecurity assessments, NIST SP 800-171 controls, SSPs, POA&Ms, and compliance reviews.
 * THIS IS AN EXAMPLE CONTRACT THAT USES UN-AUDITED CODE.
 * DO NOT USE THIS CODE IN PRODUCTION.
 */
contract DODCAR {
    // Struct to represent a DODCAR assessment record
    struct AssessmentRecord {
        string systemName; // Name of the system (e.g., "Contractor System X")
        string sspDescription; // System Security Plan (SSP) description
        string classification; // Classification level (e.g., "CUI", "Unclassified")
        mapping(string => bool) nistControls; // NIST SP 800-171 controls (e.g., "AC-1" => compliant)
        string[] controlKeys; // Array to track control keys
        mapping(string => string) poamItems; // Plan of Action and Milestones (e.g., "AC-1" => "Implement by Q1 2026")
        string[] poamKeys; // Array to track POA&M keys
        address contractor; // Contractor responsible for the system
        address reviewer; // DoD reviewer (e.g., DCMA DIBCAC)
        bool isCompliant; // Overall compliance status
        string complianceStatus; // Compliance status details (e.g., "Certified", "Pending")
        bool exists; // Flag to check if record exists
    }

    // Mapping to store assessment records by their unique ID
    mapping(bytes32 => AssessmentRecord) public assessments;

    // Event emitted when a new assessment record is created
    event AssessmentCreated(bytes32 indexed assessmentId, string systemName, address indexed contractor);
    // Event emitted when an assessment record is updated
    event AssessmentUpdated(bytes32 indexed assessmentId, string systemName, address indexed contractor);
    // Event emitted when a NIST control is added
    event ControlAdded(bytes32 indexed assessmentId, string controlKey, bool compliant);
    // Event emitted when a NIST control's compliance status is updated
    event ControlStatusUpdated(bytes32 indexed assessmentId, string controlKey, bool compliant);
    // Event emitted when a POA&M item is added
    event PoamItemAdded(bytes32 indexed assessmentId, string poamKey, string poamValue);
    // Event emitted when a compliance decision is made
    event ComplianceDecisionMade(bytes32 indexed assessmentId, string complianceStatus);

    // Modifier to check if the caller is the contractor for the assessment
    modifier onlyContractor(bytes32 assessmentId) {
        require(assessments[assessmentId].contractor == msg.sender, "Only the contractor can perform this action");
        require(assessments[assessmentId].exists, "Assessment record does not exist");
        _;
    }

    // Modifier to check if the caller is the DoD reviewer
    modifier onlyReviewer(bytes32 assessmentId) {
        require(assessments[assessmentId].reviewer == msg.sender, "Only the reviewer can perform this action");
        require(assessments[assessmentId].exists, "Assessment record does not exist");
        _;
    }

    /**
     * @dev Creates a new DODCAR assessment record.
     * @param _systemName The name of the system.
     * @param _sspDescription The System Security Plan description.
     * @param _classification The classification level (e.g., "CUI").
     * @param _reviewer The address of the DoD reviewer.
     * @return assessmentId The unique ID of the created record.
     */
    function createAssessment(
        string memory _systemName,
        string memory _sspDescription,
        string memory _classification,
        address _reviewer
    ) public returns (bytes32) {
        require(_reviewer != address(0), "Invalid reviewer address");
        // Generate a unique ID for the assessment record
        bytes32 assessmentId = keccak256(abi.encodePacked(_systemName, msg.sender, block.timestamp));
        
        // Ensure the record doesn't already exist
        require(!assessments[assessmentId].exists, "Assessment record with this ID already exists");

        // Initialize the assessment record
        AssessmentRecord storage newAssessment = assessments[assessmentId];
        newAssessment.systemName = _systemName;
        newAssessment.sspDescription = _sspDescription;
        newAssessment.classification = _classification;
        newAssessment.contractor = msg.sender;
        newAssessment.reviewer = _reviewer;
        newAssessment.isCompliant = false;
        newAssessment.complianceStatus = "Pending";
        newAssessment.exists = true;

        // Emit event for assessment creation
        emit AssessmentCreated(assessmentId, _systemName, msg.sender);

        return assessmentId;
    }

    /**
     * @dev Updates the core fields of an existing assessment record.
     * @param _assessmentId The ID of the assessment record to update.
     * @param _sspDescription The new SSP description.
     * @param _classification The new classification level.
     */
    function updateAssessment(
        bytes32 _assessmentId,
        string memory _sspDescription,
        string memory _classification
    ) public onlyContractor(_assessmentId) {
        AssessmentRecord storage assessment = assessments[_assessmentId];
        assessment.sspDescription = _sspDescription;
        assessment.classification = _classification;

        // Emit event for assessment update
        emit AssessmentUpdated(_assessmentId, assessment.systemName, msg.sender);
    }

    /**
     * @dev Adds a NIST SP 800-171 control to an assessment record.
     * @param _assessmentId The ID of the assessment record.
     * @param _controlKey The key of the control (e.g., "AC-1").
     * @param _compliant Whether the control is compliant.
     */
    function addControl(
        bytes32 _assessmentId,
        string memory _controlKey,
        bool _compliant
    ) public onlyContractor(_assessmentId) {
        assessments[_assessmentId].nistControls[_controlKey] = _compliant;
        assessments[_assessmentId].controlKeys.push(_controlKey);

        // Emit event for control addition
        emit ControlAdded(_assessmentId, _controlKey, _compliant);
    }

    /**
     * @dev Updates the compliance status of a NIST control.
     * @param _assessmentId The ID of the assessment record.
     * @param _controlKey The key of the control.
     * @param _compliant The new compliance status.
     */
    function updateControlStatus(
        bytes32 _assessmentId,
        string memory _controlKey,
        bool _compliant
    ) public onlyContractor(_assessmentId) {
        // Check if the control exists
        bool controlExists = false;
        for (uint256 i = 0; i < assessments[_assessmentId].controlKeys.length; i++) {
            if (keccak256(abi.encodePacked(assessments[_assessmentId].controlKeys[i])) == keccak256(abi.encodePacked(_controlKey))) {
                controlExists = true;
                break;
            }
        }
        require(controlExists, "Control does not exist");

        assessments[_assessmentId].nistControls[_controlKey] = _compliant;

        // Emit event for control status update
        emit ControlStatusUpdated(_assessmentId, _controlKey, _compliant);
    }

    /**
     * @dev Adds a POA&M item to an assessment record.
     * @param _assessmentId The ID of the assessment record.
     * @param _poamKey The key of the POA&M item (e.g., "AC-1").
     * @param _poamValue The action plan (e.g., "Implement by Q1 2026").
     */
    function addPoamItem(
        bytes32 _assessmentId,
        string memory _poamKey,
        string memory _poamValue
    ) public onlyContractor(_assessmentId) {
        assessments[_assessmentId].poamItems[_poamKey] = _poamValue;
        assessments[_assessmentId].poamKeys.push(_poamKey);

        // Emit event for POA&M item addition
        emit PoamItemAdded(_assessmentId, _poamKey, _poamValue);
    }

    /**
     * @dev Issues a compliance decision for an assessment record.
     * @param _assessmentId The ID of the assessment record.
     * @param _status The compliance status (e.g., "Certified", "Non-Compliant").
     */
    function makeComplianceDecision(
        bytes32 _assessmentId,
        string memory _status
    ) public onlyReviewer(_assessmentId) {
        AssessmentRecord storage assessment = assessments[_assessmentId];
        assessment.complianceStatus = _status;
        assessment.isCompliant = (keccak256(abi.encodePacked(_status)) == keccak256(abi.encodePacked("Certified")));

        // Emit event for compliance decision
        emit ComplianceDecisionMade(_assessmentId, _status);
    }

    /**
     * @dev Checks if all NIST controls for an assessment are compliant.
     * @param _assessmentId The ID of the assessment record.
     * @return Whether all controls are compliant.
     */
    function isSystemCompliant(bytes32 _assessmentId) public view returns (bool) {
        require(assessments[_assessmentId].exists, "Assessment record does not exist");
        // Check each control in the controlKeys array
        for (uint256 i = 0; i < assessments[_assessmentId].controlKeys.length; i++) {
            string memory key = assessments[_assessmentId].controlKeys[i];
            if (!assessments[_assessmentId].nistControls[key]) {
                return false;
            }
        }
        return true;
    }

    /**
     * @dev Retrieves the core fields of an assessment record.
     * @param _assessmentId The ID of the assessment record.
     * @return systemName The name of the system.
     * @return sspDescription The SSP description.
     * @return classification The classification level.
     * @return contractor The contractor address.
     * @return reviewer The reviewer address.
     * @return isCompliant The compliance status.
     * @return complianceStatus The compliance status details.
     */
    function getAssessment(bytes32 _assessmentId)
        public
        view
        returns (
            string memory systemName,
            string memory sspDescription,
            string memory classification,
            address contractor,
            address reviewer,
            bool isCompliant,
            string memory complianceStatus
        )
    {
        require(assessments[_assessmentId].exists, "Assessment record does not exist");
        AssessmentRecord storage assessment = assessments[_assessmentId];
        return (
            assessment.systemName,
            assessment.sspDescription,
            assessment.classification,
            assessment.contractor,
            assessment.reviewer,
            assessment.isCompliant,
            assessment.complianceStatus
        );
    }

    /**
     * @dev Retrieves the compliance status of a NIST control.
     * @param _assessmentId The ID of the assessment record.
     * @param _controlKey The key of the control.
     * @return The compliance status of the control.
     */
    function getControlStatus(bytes32 _assessmentId, string memory _controlKey)
        public
        view
        returns (bool)
    {
        require(assessments[_assessmentId].exists, "Assessment record does not exist");
        return assessments[_assessmentId].nistControls[_controlKey];
    }

    /**
     * @dev Retrieves the list of NIST control keys for an assessment record.
     * @param _assessmentId The ID of the assessment record.
     * @return The array of control keys.
     */
    function getControlKeys(bytes32 _assessmentId)
        public
        view
        returns (string[] memory)
    {
        require(assessments[_assessmentId].exists, "Assessment record does not exist");
        return assessments[_assessmentId].controlKeys;
    }

    /**
     * @dev Retrieves the value of a POA&M item.
     * @param _assessmentId The ID of the assessment record.
     * @param _poamKey The key of the POA&M item.
     * @return The value of the POA&M item.
     */
    function getPoamItem(bytes32 _assessmentId, string memory _poamKey)
        public
        view
        returns (string memory)
    {
        require(assessments[_assessmentId].exists, "Assessment record does not exist");
        return assessments[_assessmentId].poamItems[_poamKey];
    }

    /**
     * @dev Retrieves the list of POA&M keys for an assessment record.
     * @param _assessmentId The ID of the assessment record.
     * @return The array of POA&M keys.
     */
    function getPoamKeys(bytes32 _assessmentId)
        public
        view
        returns (string[] memory)
    {
        require(assessments[_assessmentId].exists, "Assessment record does not exist");
        return assessments[_assessmentId].poamKeys;
    }
}
