// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

/**
 * @title DoDD
 * @dev A smart contract for managing Department of Defense Directives (DoDD).
 * Supports creation, updating, and tracking of DoDD records, compliance, and responsible entities.
 * THIS IS AN EXAMPLE CONTRACT THAT USES UN-AUDITED CODE.
 * DO NOT USE THIS CODE IN PRODUCTION.
 */
contract DoDD {
    // Enum to represent DoDD categories
    enum DirectiveCategory {
        Cybersecurity,
        Intelligence,
        WorkforceManagement,
        Acquisition,
        Logistics,
        Other
    }

    // Struct to represent a DoDD record
    struct DirectiveRecord {
        string directiveNumber; // Directive number (e.g., "DoDD 8140.01")
        string title; // Directive title
        string description; // Directive description
        DirectiveCategory category; // Category of the directive
        string classification; // Classification level (e.g., "Unclassified", "Secret")
        mapping(string => bool) complianceRequirements; // Compliance requirements (e.g., "Req-1" => compliant)
        string[] requirementKeys; // Array to track requirement keys
        address[] responsibleEntities; // List of responsible DoD components (e.g., DIA, USD(P&R))
        address issuer; // Issuer of the directive (e.g., Secretary of Defense)
        bool isActive; // Directive active status
        bool exists; // Flag to check if record exists
    }

    // Mapping to store directive records by their unique ID
    mapping(bytes32 => DirectiveRecord) public directives;

    // Event emitted when a new directive record is created
    event DirectiveCreated(bytes32 indexed directiveId, string directiveNumber, address indexed issuer);
    // Event emitted when a directive record is updated
    event DirectiveUpdated(bytes32 indexed directiveId, string directiveNumber, address indexed issuer);
    // Event emitted when a compliance requirement is added
    event RequirementAdded(bytes32 indexed directiveId, string requirementKey, bool compliant);
    // Event emitted when a compliance requirement's status is updated
    event RequirementStatusUpdated(bytes32 indexed directiveId, string requirementKey, bool compliant);
    // Event emitted when a responsible entity is added
    event EntityAdded(bytes32 indexed directiveId, address indexed entity);
    // Event emitted when directive status is updated
    event DirectiveStatusUpdated(bytes32 indexed directiveId, bool isActive);

    // Modifier to check if the caller is the issuer of the directive
    modifier onlyIssuer(bytes32 directiveId) {
        require(directives[directiveId].issuer == msg.sender, "Only the issuer can perform this action");
        require(directives[directiveId].exists, "Directive record does not exist");
        _;
    }

    // Modifier to check if the caller is a responsible entity
    modifier onlyResponsibleEntity(bytes32 directiveId) {
        require(directives[directiveId].exists, "Directive record does not exist");
        bool isAuthorized = directives[directiveId].issuer == msg.sender;
        if (!isAuthorized) {
            for (uint256 i = 0; i < directives[directiveId].responsibleEntities.length; i++) {
                if (directives[directiveId].responsibleEntities[i] == msg.sender) {
                    isAuthorized = true;
                    break;
                }
            }
        }
        require(isAuthorized, "Only responsible entities can perform this action");
        _;
    }

    /**
     * @dev Creates a new DoDD record.
     * @param _directiveNumber The directive number (e.g., "DoDD 8140.01").
     * @param _title The title of the directive.
     * @param _description The description of the directive.
     * @param _category The category of the directive.
     * @param _classification The classification level (e.g., "Unclassified").
     * @param _isActive Whether the directive is active.
     * @return directiveId The unique ID of the created record.
     */
    function createDirective(
        string memory _directiveNumber,
        string memory _title,
        string memory _description,
        DirectiveCategory _category,
        string memory _classification,
        bool _isActive
    ) public returns (bytes32) {
        // Generate a unique ID for the directive record
        bytes32 directiveId = keccak256(abi.encodePacked(_directiveNumber, msg.sender, block.timestamp));
        
        // Ensure the record doesn't already exist
        require(!directives[directiveId].exists, "Directive record with this ID already exists");

        // Initialize the directive record
        DirectiveRecord storage newDirective = directives[directiveId];
        newDirective.directiveNumber = _directiveNumber;
        newDirective.title = _title;
        newDirective.description = _description;
        newDirective.category = _category;
        newDirective.classification = _classification;
        newDirective.isActive = _isActive;
        newDirective.issuer = msg.sender;
        newDirective.exists = true;
        newDirective.responsibleEntities.push(msg.sender); // Issuer is an initial responsible entity

        // Emit event for directive creation
        emit DirectiveCreated(directiveId, _directiveNumber, msg.sender);

        return directiveId;
    }

    /**
     * @dev Updates the core fields of an existing directive record.
     * @param _directiveId The ID of the directive record to update.
     * @param _title The new title.
     * @param _description The new description.
     * @param _classification The new classification level.
     */
    function updateDirective(
        bytes32 _directiveId,
        string memory _title,
        string memory _description,
        string memory _classification
    ) public onlyIssuer(_directiveId) {
        DirectiveRecord storage directive = directives[_directiveId];
        directive.title = _title;
        directive.description = _description;
        directive.classification = _classification;

        // Emit event for directive update
        emit DirectiveUpdated(_directiveId, directive.directiveNumber, msg.sender);
    }

    /**
     * @dev Adds a compliance requirement to a directive record.
     * @param _directiveId The ID of the directive record.
     * @param _requirementKey The key of the requirement (e.g., "Req-1").
     * @param _compliant Whether the requirement is compliant.
     */
    function addRequirement(
        bytes32 _directiveId,
        string memory _requirementKey,
        bool _compliant
    ) public onlyIssuer(_directiveId) {
        directives[_directiveId].complianceRequirements[_requirementKey] = _compliant;
        directives[_directiveId].requirementKeys.push(_requirementKey);

        // Emit event for requirement addition
        emit RequirementAdded(_directiveId, _requirementKey, _compliant);
    }

    /**
     * @dev Updates the compliance status of a requirement.
     * @param _directiveId The ID of the directive record.
     * @param _requirementKey The key of the requirement.
     * @param _compliant The new compliance status.
     */
    function updateRequirementStatus(
        bytes32 _directiveId,
        string memory _requirementKey,
        bool _compliant
    ) public onlyResponsibleEntity(_directiveId) {
        // Check if the requirement exists
        bool requirementExists = false;
        for (uint256 i = 0; i < directives[_directiveId].requirementKeys.length; i++) {
            if (keccak256(abi.encodePacked(directives[_directiveId].requirementKeys[i])) == keccak256(abi.encodePacked(_requirementKey))) {
                requirementExists = true;
                break;
            }
        }
        require(requirementExists, "Requirement does not exist");

        directives[_directiveId].complianceRequirements[_requirementKey] = _compliant;

        // Emit event for requirement status update
        emit RequirementStatusUpdated(_directiveId, _requirementKey, _compliant);
    }

    /**
     * @dev Adds a responsible entity to a directive record.
     * @param _directiveId The ID of the directive record.
     * @param _entity The address of the entity to add.
     */
    function addResponsibleEntity(bytes32 _directiveId, address _entity) public onlyIssuer(_directiveId) {
        require(_entity != address(0), "Invalid entity address");
        // Check if entity is already responsible
        for (uint256 i = 0; i < directives[_directiveId].responsibleEntities.length; i++) {
            require(directives[_directiveId].responsibleEntities[i] != _entity, "Entity already responsible");
        }
        directives[_directiveId].responsibleEntities.push(_entity);

        // Emit event for entity addition
        emit EntityAdded(_directiveId, _entity);
    }

    /**
     * @dev Updates the active status of a directive.
     * @param _directiveId The ID of the directive record.
     * @param _isActive The new active status.
     */
    function updateDirectiveStatus(bytes32 _directiveId, bool _isActive) public onlyIssuer(_directiveId) {
        directives[_directiveId].isActive = _isActive;

        // Emit event for directive status update
        emit DirectiveStatusUpdated(_directiveId, _isActive);
    }

    /**
     * @dev Checks if all compliance requirements for a directive are met.
     * @param _directiveId The ID of the directive record.
     * @return Whether all requirements are compliant.
     */
    function isDirectiveCompliant(bytes32 _directiveId) public view returns (bool) {
        require(directives[_directiveId].exists, "Directive record does not exist");
        // Check each requirement in the requirementKeys array
        for (uint256 i = 0; i < directives[_directiveId].requirementKeys.length; i++) {
            string memory key = directives[_directiveId].requirementKeys[i];
            if (!directives[_directiveId].complianceRequirements[key]) {
                return false;
            }
        }
        return true;
    }

    /**
     * @dev Retrieves the core fields of a directive record.
     * @param _directiveId The ID of the directive record.
     * @return directiveNumber The directive number.
     * @return title The title of the directive.
     * @return description The description of the directive.
     * @return category The category of the directive.
     * @return classification The classification level.
     * @return isActive The active status.
     * @return issuer The issuer of the record.
     */
    function getDirective(bytes32 _directiveId)
        public
        view
        onlyResponsibleEntity(_directiveId)
        returns (
            string memory directiveNumber,
            string memory title,
            string memory description,
            DirectiveCategory category,
            string memory classification,
            bool isActive,
            address issuer
        )
    {
        require(directives[_directiveId].exists, "Directive record does not exist");
        DirectiveRecord storage directive = directives[_directiveId];
        return (
            directive.directiveNumber,
            directive.title,
            directive.description,
            directive.category,
            directive.classification,
            directive.isActive,
            directive.issuer
        );
    }

    /**
     * @dev Retrieves the compliance status of a requirement.
     * @param _directiveId The ID of the directive record.
     * @param _requirementKey The key of the requirement.
     * @return The compliance status of the requirement.
     */
    function getRequirementStatus(bytes32 _directiveId, string memory _requirementKey)
        public
        view
        onlyResponsibleEntity(_directiveId)
        returns (bool)
    {
        require(directives[_directiveId].exists, "Directive record does not exist");
        return directives[_directiveId].complianceRequirements[_requirementKey];
    }

    /**
     * @dev Retrieves the list of requirement keys for a directive record.
     * @param _directiveId The ID of the directive record.
     * @return The array of requirement keys.
     */
    function getRequirementKeys(bytes32 _directiveId)
        public
        view
        onlyResponsibleEntity(_directiveId)
        returns (string[] memory)
    {
        require(directives[_directiveId].exists, "Directive record does not exist");
        return directives[_directiveId].requirementKeys;
    }

    /**
     * @dev Retrieves the list of responsible entities for a directive record.
     * @param _directiveId The ID of the directive record.
     * @return The array of responsible entity addresses.
     */
    function getResponsibleEntities(bytes32 _directiveId)
        public
        view
        onlyIssuer(_directiveId)
        returns (address[] memory)
    {
        require(directives[_directiveId].exists, "Directive record does not exist");
        return directives[_directiveId].responsibleEntities;
    }

    /**
     * @dev Retrieves publicly accessible directive details (e.g., for unclassified directives).
     * @param _directiveId The ID of the directive record.
     * @return directiveNumber The directive number.
     * @return title The title of the directive.
     * @return description The description of the directive.
     */
    function getPublicDirectiveDetails(bytes32 _directiveId)
        public
        view
        returns (
            string memory directiveNumber,
            string memory title,
            string memory description
        )
    {
        require(directives[_directiveId].exists, "Directive record does not exist");
        require(
            keccak256(abi.encodePacked(directives[_directiveId].classification)) == keccak256(abi.encodePacked("Unclassified")),
            "Directive is not unclassified"
        );
        DirectiveRecord storage directive = directives[_directiveId];
        return (directive.directiveNumber, directive.title, directive.description);
    }
}