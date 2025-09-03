// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

/**
 * @title DoDI
 * @dev A smart contract for managing Department of Defense Instructions (DoDI).
 * Supports creation, updating, and tracking of DoDI records, compliance, and responsible entities.
 * THIS IS AN EXAMPLE CONTRACT THAT USES UN-AUDITED CODE.
 * DO NOT USE THIS CODE IN PRODUCTION.
 */
contract DoDI {
    // Enum to represent DoDI categories
    enum InstructionCategory {
        Cybersecurity,
        Intelligence,
        Acquisition,
        WorkforceManagement,
        Logistics,
        Other
    }

    // Struct to represent a DoDI record
    struct InstructionRecord {
        string instructionNumber; // Instruction number (e.g., "DoDI 8510.01")
        string title; // Instruction title
        string description; // Instruction description
        InstructionCategory category; // Category of the instruction
        string classification; // Classification level (e.g., "Unclassified", "Secret")
        mapping(string => bool) complianceRequirements; // Compliance requirements (e.g., "Proc-1" => compliant)
        string[] requirementKeys; // Array to track requirement keys
        address[] responsibleEntities; // List of responsible DoD components (e.g., DIA, USD(A&S))
        address issuer; // Issuer of the instruction (e.g., USD(P&R))
        bool isActive; // Instruction active status
        bool exists; // Flag to check if record exists
    }

    // Mapping to store instruction records by their unique ID
    mapping(bytes32 => InstructionRecord) public instructions;

    // Event emitted when a new instruction record is created
    event InstructionCreated(bytes32 indexed instructionId, string instructionNumber, address indexed issuer);
    // Event emitted when an instruction record is updated
    event InstructionUpdated(bytes32 indexed instructionId, string instructionNumber, address indexed issuer);
    // Event emitted when a compliance requirement is added
    event RequirementAdded(bytes32 indexed instructionId, string requirementKey, bool compliant);
    // Event emitted when a compliance requirement's status is updated
    event RequirementStatusUpdated(bytes32 indexed instructionId, string requirementKey, bool compliant);
    // Event emitted when a responsible entity is added
    event EntityAdded(bytes32 indexed instructionId, address indexed entity);
    // Event emitted when instruction status is updated
    event InstructionStatusUpdated(bytes32 indexed instructionId, bool isActive);

    // Modifier to check if the caller is the issuer of the instruction
    modifier onlyIssuer(bytes32 instructionId) {
        require(instructions[instructionId].issuer == msg.sender, "Only the issuer can perform this action");
        require(instructions[instructionId].exists, "Instruction record does not exist");
        _;
    }

    // Modifier to check if the caller is a responsible entity
    modifier onlyResponsibleEntity(bytes32 instructionId) {
        require(instructions[instructionId].exists, "Instruction record does not exist");
        bool isAuthorized = instructions[instructionId].issuer == msg.sender;
        if (!isAuthorized) {
            for (uint256 i = 0; i < instructions[instructionId].responsibleEntities.length; i++) {
                if (instructions[instructionId].responsibleEntities[i] == msg.sender) {
                    isAuthorized = true;
                    break;
                }
            }
        }
        require(isAuthorized, "Only responsible entities can perform this action");
        _;
    }

    /**
     * @dev Creates a new DoDI record.
     * @param _instructionNumber The instruction number (e.g., "DoDI 8510.01").
     * @param _title The title of the instruction.
     * @param _description The description of the instruction.
     * @param _category The category of the instruction.
     * @param _classification The classification level (e.g., "Unclassified").
     * @param _isActive Whether the instruction is active.
     * @return instructionId The unique ID of the created record.
     */
    function createInstruction(
        string memory _instructionNumber,
        string memory _title,
        string memory _description,
        InstructionCategory _category,
        string memory _classification,
        bool _isActive
    ) public returns (bytes32) {
        // Generate a unique ID for the instruction record
        bytes32 instructionId = keccak256(abi.encodePacked(_instructionNumber, msg.sender, block.timestamp));
        
        // Ensure the record doesn't already exist
        require(!instructions[instructionId].exists, "Instruction record with this ID already exists");

        // Initialize the instruction record
        InstructionRecord storage newInstruction = instructions[instructionId];
        newInstruction.instructionNumber = _instructionNumber;
        newInstruction.title = _title;
        newInstruction.description = _description;
        newInstruction.category = _category;
        newInstruction.classification = _classification;
        newInstruction.isActive = _isActive;
        newInstruction.issuer = msg.sender;
        newInstruction.exists = true;
        newInstruction.responsibleEntities.push(msg.sender); // Issuer is an initial responsible entity

        // Emit event for instruction creation
        emit InstructionCreated(instructionId, _instructionNumber, msg.sender);

        return instructionId;
    }

    /**
     * @dev Updates the core fields of an existing instruction record.
     * @param _instructionId The ID of the instruction record to update.
     * @param _title The new title.
     * @param _description The new description.
     * @param _classification The new classification level.
     */
    function updateInstruction(
        bytes32 _instructionId,
        string memory _title,
        string memory _description,
        string memory _classification
    ) public onlyIssuer(_instructionId) {
        InstructionRecord storage instruction = instructions[_instructionId];
        instruction.title = _title;
        instruction.description = _description;
        instruction.classification = _classification;

        // Emit event for instruction update
        emit InstructionUpdated(_instructionId, instruction.instructionNumber, msg.sender);
    }

    /**
     * @dev Adds a compliance requirement to an instruction record.
     * @param _instructionId The ID of the instruction record.
     * @param _requirementKey The key of the requirement (e.g., "Proc-1").
     * @param _compliant Whether the requirement is compliant.
     */
    function addRequirement(
        bytes32 _instructionId,
        string memory _requirementKey,
        bool _compliant
    ) public onlyIssuer(_instructionId) {
        instructions[_instructionId].complianceRequirements[_requirementKey] = _compliant;
        instructions[_instructionId].requirementKeys.push(_requirementKey);

        // Emit event for requirement addition
        emit RequirementAdded(_instructionId, _requirementKey, _compliant);
    }

    /**
     * @dev Updates the compliance status of a requirement.
     * @param _instructionId The ID of the instruction record.
     * @param _requirementKey The key of the requirement.
     * @param _compliant The new compliance status.
     */
    function updateRequirementStatus(
        bytes32 _instructionId,
        string memory _requirementKey,
        bool _compliant
    ) public onlyResponsibleEntity(_instructionId) {
        // Check if the requirement exists
        bool requirementExists = false;
        for (uint256 i = 0; i < instructions[_instructionId].requirementKeys.length; i++) {
            if (keccak256(abi.encodePacked(instructions[_instructionId].requirementKeys[i])) == keccak256(abi.encodePacked(_requirementKey))) {
                requirementExists = true;
                break;
            }
        }
        require(requirementExists, "Requirement does not exist");

        instructions[_instructionId].complianceRequirements[_requirementKey] = _compliant;

        // Emit event for requirement status update
        emit RequirementStatusUpdated(_instructionId, _requirementKey, _compliant);
    }

    /**
     * @dev Adds a responsible entity to an instruction record.
     * @param _instructionId The ID of the instruction record.
     * @param _entity The address of the entity to add.
     */
    function addResponsibleEntity(bytes32 _instructionId, address _entity) public onlyIssuer(_instructionId) {
        require(_entity != address(0), "Invalid entity address");
        // Check if entity is already responsible
        for (uint256 i = 0; i < instructions[_instructionId].responsibleEntities.length; i++) {
            require(instructions[_instructionId].responsibleEntities[i] != _entity, "Entity already responsible");
        }
        instructions[_instructionId].responsibleEntities.push(_entity);

        // Emit event for entity addition
        emit EntityAdded(_instructionId, _entity);
    }

    /**
     * @dev Updates the active status of an instruction.
     * @param _instructionId The ID of the instruction record.
     * @param _isActive The new active status.
     */
    function updateInstructionStatus(bytes32 _instructionId, bool _isActive) public onlyIssuer(_instructionId) {
        instructions[_instructionId].isActive = _isActive;

        // Emit event for instruction status update
        emit InstructionStatusUpdated(_instructionId, _isActive);
    }

    /**
     * @dev Checks if all compliance requirements for an instruction are met.
     * @param _instructionId The ID of the instruction record.
     * @return Whether all requirements are compliant.
     */
    function isInstructionCompliant(bytes32 _instructionId) public view returns (bool) {
        require(instructions[_instructionId].exists, "Instruction record does not exist");
        // Check each requirement in the requirementKeys array
        for (uint256 i = 0; i < instructions[_instructionId].requirementKeys.length; i++) {
            string memory key = instructions[_instructionId].requirementKeys[i];
            if (!instructions[_instructionId].complianceRequirements[key]) {
                return false;
            }
        }
        return true;
    }

    /**
     * @dev Retrieves the core fields of an instruction record.
     * @param _instructionId The ID of the instruction record.
     * @return instructionNumber The instruction number.
     * @return title The title of the instruction.
     * @return description The description of the instruction.
     * @return category The category of the instruction.
     * @return classification The classification level.
     * @return isActive The active status.
     * @return issuer The issuer of the record.
     */
    function getInstruction(bytes32 _instructionId)
        public
        view
        onlyResponsibleEntity(_instructionId)
        returns (
            string memory instructionNumber,
            string memory title,
            string memory description,
            InstructionCategory category,
            string memory classification,
            bool isActive,
            address issuer
        )
    {
        require(instructions[_instructionId].exists, "Instruction record does not exist");
        InstructionRecord storage instruction = instructions[_instructionId];
        return (
            instruction.instructionNumber,
            instruction.title,
            instruction.description,
            instruction.category,
            instruction.classification,
            instruction.isActive,
            instruction.issuer
        );
    }

    /**
     * @dev Retrieves the compliance status of a requirement.
     * @param _instructionId The ID of the instruction record.
     * @param _requirementKey The key of the requirement.
     * @return The compliance status of the requirement.
     */
    function getRequirementStatus(bytes32 _instructionId, string memory _requirementKey)
        public
        view
        onlyResponsibleEntity(_instructionId)
        returns (bool)
    {
        require(instructions[_instructionId].exists, "Instruction record does not exist");
        return instructions[_instructionId].complianceRequirements[_requirementKey];
    }

    /**
     * @dev Retrieves the list of requirement keys for an instruction record.
     * @param _instructionId The ID of the instruction record.
     * @return The array of requirement keys.
     */
    function getRequirementKeys(bytes32 _instructionId)
        public
        view
        onlyResponsibleEntity(_instructionId)
        returns (string[] memory)
    {
        require(instructions[_instructionId].exists, "Instruction record does not exist");
        return instructions[_instructionId].requirementKeys;
    }

    /**
     * @dev Retrieves the list of responsible entities for an instruction record.
     * @param _instructionId The ID of the instruction record.
     * @return The array of responsible entity addresses.
     */
    function getResponsibleEntities(bytes32 _instructionId)
        public
        view
        onlyIssuer(_instructionId)
        returns (address[] memory)
    {
        require(instructions[_instructionId].exists, "Instruction record does not exist");
        return instructions[_instructionId].responsibleEntities;
    }

    /**
     * @dev Retrieves publicly accessible instruction details (e.g., for unclassified instructions).
     * @param _instructionId The ID of the instruction record.
     * @return instructionNumber The instruction number.
     * @return title The title of the instruction.
     * @return description The description of the instruction.
     */
    function getPublicInstructionDetails(bytes32 _instructionId)
        public
        view
        returns (
            string memory instructionNumber,
            string memory title,
            string memory description
        )
    {
        require(instructions[_instructionId].exists, "Instruction record does not exist");
        require(
            keccak256(abi.encodePacked(instructions[_instructionId].classification)) == keccak256(abi.encodePacked("Unclassified")),
            "Instruction is not unclassified"
        );
        InstructionRecord storage instruction = instructions[_instructionId];
        return (instruction.instructionNumber, instruction.title, instruction.description);
    }
}