// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

/**
 * @title DoDCybersecurityAnalysisAndReview
 * @dev A smart contract for managing DoD Cybersecurity Analysis and Review records.
 * Enables creation, management, and verification of cybersecurity compliance assessments.
 * THIS IS AN EXAMPLE CONTRACT THAT USES UN-AUDITED CODE.
 * DO NOT USE THIS CODE IN PRODUCTION.
 */
contract DoDCybersecurityAnalysisAndReview {
    // Struct to represent a Cybersecurity Analysis and Review (CAR)
    struct CAR {
        string name; // Name of the review (e.g., "Contractor XYZ CMMC Assessment")
        string description; // Description of the review (e.g., scope, purpose)
        mapping(string => bool) requirements; // Security requirements and their compliance status
        string[] requirementKeys; // Array to track defined requirement keys
        address owner; // Owner of the CAR (e.g., contractor or auditor)
        address[] auditors; // List of authorized auditors
        bool exists; // Flag to check if CAR exists
        uint256 cmmcLevel; // CMMC level targeted (1, 2, or 3)
    }

    // Mapping to store CARs by their unique ID
    mapping(bytes32 => CAR) public cars;

    // Event emitted when a new CAR is created
    event CARCreated(bytes32 indexed carId, string name, address indexed owner, uint256 cmmcLevel);
    // Event emitted when a CAR is updated
    event CARUpdated(bytes32 indexed carId, string name, address indexed owner);
    // Event emitted when a requirement is added
    event RequirementAdded(bytes32 indexed carId, string requirementKey, bool required);
    // Event emitted when a requirement's compliance status is updated
    event RequirementStatusUpdated(bytes32 indexed carId, string requirementKey, bool compliant);
    // Event emitted when an auditor is added
    event AuditorAdded(bytes32 indexed carId, address indexed auditor);

    // Modifier to check if the caller is the owner of the CAR
    modifier onlyCAROwner(bytes32 carId) {
        require(cars[carId].owner == msg.sender, "Only the CAR owner can perform this action");
        require(cars[carId].exists, "CAR does not exist");
        _;
    }

    // Modifier to check if the caller is an authorized auditor
    modifier onlyAuditor(bytes32 carId) {
        require(cars[carId].exists, "CAR does not exist");
        bool isAuditor = false;
        for (uint256 i = 0; i < cars[carId].auditors.length; i++) {
            if (cars[carId].auditors[i] == msg.sender) {
                isAuditor = true;
                break;
            }
        }
        require(isAuditor, "Only authorized auditors can perform this action");
        _;
    }

    /**
     * @dev Creates a new Cybersecurity Analysis and Review record.
     * @param _name The name of the CAR.
     * @param _description A description of the CAR.
     * @param _cmmcLevel The targeted CMMC level (1, 2, or 3).
     * @return carId The unique ID of the created CAR.
     */
    function createCAR(string memory _name, string memory _description, uint256 _cmmcLevel) public returns (bytes32) {
        require(_cmmcLevel >= 1 && _cmmcLevel <= 3, "CMMC level must be 1, 2, or 3");
        // Generate a unique ID for the CAR
        bytes32 carId = keccak256(abi.encodePacked(_name, msg.sender, block.timestamp));
        
        // Ensure the CAR doesn't already exist
        require(!cars[carId].exists, "CAR with this ID already exists");

        // Initialize the CAR
        CAR storage newCAR = cars[carId];
        newCAR.name = _name;
        newCAR.description = _description;
        newCAR.owner = msg.sender;
        newCAR.cmmcLevel = _cmmcLevel;
        newCAR.exists = true;
        newCAR.auditors.push(msg.sender); // Owner is also an initial auditor

        // Emit event for CAR creation
        emit CARCreated(carId, _name, msg.sender, _cmmcLevel);

        return carId;
    }

    /**
     * @dev Updates the description of an existing CAR.
     * @param _carId The ID of the CAR to update.
     * @param _newDescription The new description for the CAR.
     */
    function updateCARDescription(bytes32 _carId, string memory _newDescription) public onlyCAROwner(_carId) {
        cars[_carId].description = _newDescription;

        // Emit event for CAR update
        emit CARUpdated(_carId, cars[_carId].name, msg.sender);
    }

    /**
     * @dev Adds an auditor to a CAR.
     * @param _carId The ID of the CAR.
     * @param _auditor The address of the auditor to add.
     */
    function addAuditor(bytes32 _carId, address _auditor) public onlyCAROwner(_carId) {
        require(_auditor != address(0), "Invalid auditor address");
        // Check if auditor is already added
        for (uint256 i = 0; i < cars[_carId].auditors.length; i++) {
            require(cars[_carId].auditors[i] != _auditor, "Auditor already exists");
        }
        cars[_carId].auditors.push(_auditor);

        // Emit event for auditor addition
        emit AuditorAdded(_carId, _auditor);
    }

    /**
     * @dev Adds a requirement to a CAR (e.g., NIST SP 800-171 control).
     * @param _carId The ID of the CAR.
     * @param _requirementKey The name of the requirement (e.g., "AC.1.001").
     * @param _required Whether the requirement is mandatory for compliance.
     */
    function addRequirement(bytes32 _carId, string memory _requirementKey, bool _required) public onlyCAROwner(_carId) {
        cars[_carId].requirements[_requirementKey] = _required;
        cars[_carId].requirementKeys.push(_requirementKey);

        // Emit event for requirement addition
        emit RequirementAdded(_carId, _requirementKey, _required);
    }

    /**
     * @dev Updates the compliance status of a requirement.
     * @param _carId The ID of the CAR.
     * @param _requirementKey The name of the requirement.
     * @param _compliant Whether the requirement is compliant.
     */
    function updateRequirementStatus(bytes32 _carId, string memory _requirementKey, bool _compliant) public onlyAuditor(_carId) {
        // Check if the requirement exists
        bool requirementExists = false;
        for (uint256 i = 0; i < cars[_carId].requirementKeys.length; i++) {
            if (keccak256(abi.encodePacked(cars[_carId].requirementKeys[i])) == keccak256(abi.encodePacked(_requirementKey))) {
                requirementExists = true;
                break;
            }
        }
        require(requirementExists, "Requirement does not exist");

        cars[_carId].requirements[_requirementKey] = _compliant;

        // Emit event for requirement status update
        emit RequirementStatusUpdated(_carId, _requirementKey, _compliant);
    }

    /**
     * @dev Checks if all required requirements for a CAR are compliant.
     * @param _carId The ID of the CAR.
     * @return Whether the CAR is compliant with all required requirements.
     */
    function isCARCompliant(bytes32 _carId) public view returns (bool) {
        require(cars[_carId].exists, "CAR does not exist");
        // Check each requirement in the requirementKeys array
        for (uint256 i = 0; i < cars[_carId].requirementKeys.length; i++) {
            string memory key = cars[_carId].requirementKeys[i];
            // If the requirement is required (true) but not compliant (false), return false
            if (cars[_carId].requirements[key] && !cars[_carId].requirements[key]) {
                return false;
            }
        }
        return true;
    }

    /**
     * @dev Retrieves the details of a CAR.
     * @param _carId The ID of the CAR.
     * @return name The name of the CAR.
     * @return description The description of the CAR.
     * @return owner The owner of the CAR.
     * @return cmmcLevel The targeted CMMC level.
     */
    function getCAR(bytes32 _carId) public view returns (string memory name, string memory description, address owner, uint256 cmmcLevel) {
        require(cars[_carId].exists, "CAR does not exist");
        CAR storage car = cars[_carId];
        return (car.name, car.description, car.owner, car.cmmcLevel);
    }

    /**
     * @dev Retrieves the compliance status of a specific requirement.
     * @param _carId The ID of the CAR.
     * @param _requirementKey The name of the requirement.
     * @return The compliance status of the requirement.
     */
    function getRequirementStatus(bytes32 _carId, string memory _requirementKey) public view returns (bool) {
        require(cars[_carId].exists, "CAR does not exist");
        return cars[_carId].requirements[_requirementKey];
    }

    /**
     * @dev Retrieves the list of requirement keys for a CAR.
     * @param _carId The ID of the CAR.
     * @return The array of requirement keys.
     */
    function getRequirementKeys(bytes32 _carId) public view returns (string[] memory) {
        require(cars[_carId].exists, "CAR does not exist");
        return cars[_carId].requirementKeys;
    }

    /**
     * @dev Retrieves the list of auditors for a CAR.
     * @param _carId The ID of the CAR.
     * @return The array of auditor addresses.
     */
    function getAuditors(bytes32 _carId) public view returns (address[] memory) {
        require(cars[_carId].exists, "CAR does not exist");
        return cars[_carId].auditors;
    }
}
