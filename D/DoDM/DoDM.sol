// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

/**
 * @title DoDM
 * @dev A smart contract for managing Department of Defense Manuals (DoDM).
 * Supports creation, updating, and tracking of DoDM records, compliance, and responsible entities.
 * THIS IS AN EXAMPLE CONTRACT THAT USES UN-AUDITED CODE.
 * DO NOT USE THIS CODE IN PRODUCTION.
 */
contract DoDM {
    // Enum to represent DoDM categories
    enum ManualCategory {
        Cybersecurity,
        Acquisition,
        Logistics,
        PersonnelManagement,
        Security,
        Other
    }

    // Struct to represent a DoDM record
    struct ManualRecord {
        string manualNumber; // Manual number (e.g., "DoDM 5200.01")
        string title; // Manual title
        string description; // Manual description
        ManualCategory category; // Category of the manual
        string classification; // Classification level (e.g., "Unclassified", "Secret")
        mapping(string => bool) complianceRequirements; // Compliance requirements (e.g., "Guideline-1" => compliant)
        string[] requirementKeys; // Array to track requirement keys
        address[] responsibleEntities; // List of responsible DoD components (e.g., DIA, USD(A&S))
        address issuer; // Issuer of the manual (e.g., USD(P&R))
        bool isActive; // Manual active status
        bool exists; // Flag to check if record exists
    }

    // Mapping to store manual records by their unique ID
    mapping(bytes32 => ManualRecord) public manuals;

    // Event emitted when a new manual record is created
    event ManualCreated(bytes32 indexed manualId, string manualNumber, address indexed issuer);
    // Event emitted when a manual record is updated
    event ManualUpdated(bytes32 indexed manualId, string manualNumber, address indexed issuer);
    // Event emitted when a compliance requirement is added
    event RequirementAdded(bytes32 indexed manualId, string requirementKey, bool compliant);
    // Event emitted when a compliance requirement's status is updated
    event RequirementStatusUpdated(bytes32 indexed manualId, string requirementKey, bool compliant);
    // Event emitted when a responsible entity is added
    event EntityAdded(bytes32 indexed manualId, address indexed entity);
    // Event emitted when manual status is updated
    event ManualStatusUpdated(bytes32 indexed manualId, bool isActive);

    // Modifier to check if the caller is the issuer of the manual
    modifier onlyIssuer(bytes32 manualId) {
        require(manuals[manualId].issuer == msg.sender, "Only the issuer can perform this action");
        require(manuals[manualId].exists, "Manual record does not exist");
        _;
    }

    // Modifier to check if the caller is a responsible entity
    modifier onlyResponsibleEntity(bytes32 manualId) {
        require(manuals[manualId].exists, "Manual record does not exist");
        bool isAuthorized = manuals[manualId].issuer == msg.sender;
        if (!isAuthorized) {
            for (uint256 i = 0; i < manuals[manualId].responsibleEntities.length; i++) {
                if (manuals[manualId].responsibleEntities[i] == msg.sender) {
                    isAuthorized = true;
                    break;
                }
            }
        }
        require(isAuthorized, "Only responsible entities can perform this action");
        _;
    }

    /**
     * @dev Creates a new DoDM record.
     * @param _manualNumber The manual number (e.g., "DoDM 5200.01").
     * @param _title The title of the manual.
     * @param _description The description of the manual.
     * @param _category The category of the manual.
     * @param _classification The classification level (e.g., "Unclassified").
     * @param _isActive Whether the manual is active.
     * @return manualId The unique ID of the created record.
     */
    function createManual(
        string memory _manualNumber,
        string memory _title,
        string memory _description,
        ManualCategory _category,
        string memory _classification,
        bool _isActive
    ) public returns (bytes32) {
        // Generate a unique ID for the manual record
        bytes32 manualId = keccak256(abi.encodePacked(_manualNumber, msg.sender, block.timestamp));
        
        // Ensure the record doesn't already exist
        require(!manuals[manualId].exists, "Manual record with this ID already exists");

        // Initialize the manual record
        ManualRecord storage newManual = manuals[manualId];
        newManual.manualNumber = _manualNumber;
        newManual.title = _title;
        newManual.description = _description;
        newManual.category = _category;
        newManual.classification = _classification;
        newManual.isActive = _isActive;
        newManual.issuer = msg.sender;
        newManual.exists = true;
        newManual.responsibleEntities.push(msg.sender); // Issuer is an initial responsible entity

        // Emit event for manual creation
        emit ManualCreated(manualId, _manualNumber, msg.sender);

        return manualId;
    }

    /**
     * @dev Updates the core fields of an existing manual record.
     * @param _manualId The ID of the manual record to update.
     * @param _title The new title.
     * @param _description The new description.
     * @param _classification The new classification level.
     */
    function updateManual(
        bytes32 _manualId,
        string memory _title,
        string memory _description,
        string memory _classification
    ) public onlyIssuer(_manualId) {
        ManualRecord storage manual = manuals[_manualId];
        manual.title = _title;
        manual.description = _description;
        manual.classification = _classification;

        // Emit event for manual update
        emit ManualUpdated(_manualId, manual.manualNumber, msg.sender);
    }

    /**
     * @dev Adds a compliance requirement to a manual record.
     * @param _manualId The ID of the manual record.
     * @param _requirementKey The key of the requirement (e.g., "Guideline-1").
     * @param _compliant Whether the requirement is compliant.
     */
    function addRequirement(
        bytes32 _manualId,
        string memory _requirementKey,
        bool _compliant
    ) public onlyIssuer(_manualId) {
        manuals[_manualId].complianceRequirements[_requirementKey] = _compliant;
        manuals[_manualId].requirementKeys.push(_requirementKey);

        // Emit event for requirement addition
        emit RequirementAdded(_manualId, _requirementKey, _compliant);
    }

    /**
     * @dev Updates the compliance status of a requirement.
     * @param _manualId The ID of the manual record.
     * @param _requirementKey The key of the requirement.
     * @param _compliant The new compliance status.
     */
    function updateRequirementStatus(
        bytes32 _manualId,
        string memory _requirementKey,
        bool _compliant
    ) public onlyResponsibleEntity(_manualId) {
        // Check if the requirement exists
        bool requirementExists = false;
        for (uint256 i = 0; i < manuals[_manualId].requirementKeys.length; i++) {
            if (keccak256(abi.encodePacked(manuals[_manualId].requirementKeys[i])) == keccak256(abi.encodePacked(_requirementKey))) {
                requirementExists = true;
                break;
            }
        }
        require(requirementExists, "Requirement does not exist");

        manuals[_manualId].complianceRequirements[_requirementKey] = _compliant;

        // Emit event for requirement status update
        emit RequirementStatusUpdated(_manualId, _requirementKey, _compliant);
    }

    /**
     * @dev Adds a responsible entity to a manual record.
     * @param _manualId The ID of the manual record.
     * @param _entity The address of the entity to add.
     */
    function addResponsibleEntity(bytes32 _manualId, address _entity) public onlyIssuer(_manualId) {
        require(_entity != address(0), "Invalid entity address");
        // Check if entity is already responsible
        for (uint256 i = 0; i < manuals[_manualId].responsibleEntities.length; i++) {
            require(manuals[_manualId].responsibleEntities[i] != _entity, "Entity already responsible");
        }
        manuals[_manualId].responsibleEntities.push(_entity);

        // Emit event for entity addition
        emit EntityAdded(_manualId, _entity);
    }

    /**
     * @dev Updates the active status of a manual.
     * @param _manualId The ID of the manual record.
     * @param _isActive The new active status.
     */
    function updateManualStatus(bytes32 _manualId, bool _isActive) public onlyIssuer(_manualId) {
        manuals[_manualId].isActive = _isActive;

        // Emit event for manual status update
        emit ManualStatusUpdated(_manualId, _isActive);
    }

    /**
     * @dev Checks if all compliance requirements for a manual are met.
     * @param _manualId The ID of the manual record.
     * @return Whether all requirements are compliant.
     */
    function isManualCompliant(bytes32 _manualId) public view returns (bool) {
        require(manuals[_manualId].exists, "Manual record does not exist");
        // Check each requirement in the requirementKeys array
        for (uint256 i = 0; i < manuals[_manualId].requirementKeys.length; i++) {
            string memory key = manuals[_manualId].requirementKeys[i];
            if (!manuals[_manualId].complianceRequirements[key]) {
                return false;
            }
        }
        return true;
    }

    /**
     * @dev Retrieves the core fields of a manual record.
     * @param _manualId The ID of the manual record.
     * @return manualNumber The manual number.
     * @return title The title of the manual.
     * @return description The description of the manual.
     * @return category The category of the manual.
     * @return classification The classification level.
     * @return isActive The active status.
     * @return issuer The issuer of the record.
     */
    function getManual(bytes32 _manualId)
        public
        view
        onlyResponsibleEntity(_manualId)
        returns (
            string memory manualNumber,
            string memory title,
            string memory description,
            ManualCategory category,
            string memory classification,
            bool isActive,
            address issuer
        )
    {
        require(manuals[_manualId].exists, "Manual record does not exist");
        ManualRecord storage manual = manuals[_manualId];
        return (
            manual.manualNumber,
            manual.title,
            manual.description,
            manual.category,
            manual.classification,
            manual.isActive,
            manual.issuer
        );
    }

    /**
     * @dev Retrieves the compliance status of a requirement.
     * @param _manualId The ID of the manual record.
     * @param _requirementKey The key of the requirement.
     * @return The compliance status of the requirement.
     */
    function getRequirementStatus(bytes32 _manualId, string memory _requirementKey)
        public
        view
        onlyResponsibleEntity(_manualId)
        returns (bool)
    {
        require(manuals[_manualId].exists, "Manual record does not exist");
        return manuals[_manualId].complianceRequirements[_requirementKey];
    }

    /**
     * @dev Retrieves the list of requirement keys for a manual record.
     * @param _manualId The ID of the manual record.
     * @return The array of requirement keys.
     */
    function getRequirementKeys(bytes32 _manualId)
        public
        view
        onlyResponsibleEntity(_manualId)
        returns (string[] memory)
    {
        require(manuals[_manualId].exists, "Manual record does not exist");
        return manuals[_manualId].requirementKeys;
    }

    /**
     * @dev Retrieves the list of responsible entities for a manual record.
     * @param _manualId The ID of the manual record.
     * @return The array of responsible entity addresses.
     */
    function getResponsibleEntities(bytes32 _manualId)
        public
        view
        onlyIssuer(_manualId)
        returns (address[] memory)
    {
        require(manuals[_manualId].exists, "Manual record does not exist");
        return manuals[_manualId].responsibleEntities;
    }

    /**
     * @dev Retrieves publicly accessible manual details (e.g., for unclassified manuals).
     * @param _manualId The ID of the manual record.
     * @return manualNumber The manual number.
     * @return title The title of the manual.
     * @return description The description of the manual.
     */
    function getPublicManualDetails(bytes32 _manualId)
        public
        view
        returns (
            string memory manualNumber,
            string memory title,
            string memory description
        )
    {
        require(manuals[_manualId].exists, "Manual record does not exist");
        require(
            keccak256(abi.encodePacked(manuals[_manualId].classification)) == keccak256(abi.encodePacked("Unclassified")),
            "Manual is not unclassified"
        );
        ManualRecord storage manual = manuals[_manualId];
        return (manual.manualNumber, manual.title, manual.description);
    }
}