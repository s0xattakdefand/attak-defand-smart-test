// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

/**
 * @title DoDCyberspaceStrategy
 * @dev A smart contract for managing DoD Strategy for Operating in Cyberspace records.
 * Supports tracking cyber operations, initiatives, security controls, and partnerships.
 * THIS IS AN EXAMPLE CONTRACT THAT USES UN-AUDITED CODE.
 * DO NOT USE THIS CODE IN PRODUCTION.
 */
contract DoDCyberspaceStrategy {
    // Enum to represent the five strategic initiatives from the 2011 DoD Strategy
    enum StrategicInitiative {
        OperationalDomain, // Treat cyberspace as an operational domain
        DefenseConcepts,  // Employ new defense operating concepts
        GovernmentPartnerships, // Partner with U.S. government agencies and private sector
        InternationalAlliances, // Build relationships with allies and partners
        CyberWorkforce     // Leverage cyber workforce and innovation
    }

    // Struct to represent a Cyber Operation record
    struct CyberOperation {
        string operationName; // Name of the cyber operation (e.g., "Cyber Defense 2025")
        string description; // Description of the operation
        StrategicInitiative initiative; // Associated strategic initiative
        string classification; // Classification level (e.g., "Unclassified", "Secret")
        mapping(string => bool) securityControls; // Security controls (e.g., "SC-1" => compliant)
        string[] controlKeys; // Array to track control keys
        address[] partners; // List of authorized partners (e.g., allies, agencies)
        address owner; // Owner of the record (e.g., DoD administrator)
        bool exists; // Flag to check if record exists
    }

    // Mapping to store cyber operation records by their unique ID
    mapping(bytes32 => CyberOperation) public operations;

    // Event emitted when a new cyber operation record is created
    event OperationCreated(bytes32 indexed operationId, string operationName, address indexed owner, StrategicInitiative initiative);
    // Event emitted when a cyber operation record is updated
    event OperationUpdated(bytes32 indexed operationId, string operationName, address indexed owner);
    // Event emitted when a security control is added
    event SecurityControlAdded(bytes32 indexed operationId, string controlKey, bool compliant);
    // Event emitted when a security control's compliance status is updated
    event SecurityControlStatusUpdated(bytes32 indexed operationId, string controlKey, bool compliant);
    // Event emitted when a partner is added
    event PartnerAdded(bytes32 indexed operationId, address indexed partner);

    // Modifier to check if the caller is the owner of the operation record
    modifier onlyOperationOwner(bytes32 operationId) {
        require(operations[operationId].owner == msg.sender, "Only the operation owner can perform this action");
        require(operations[operationId].exists, "Operation record does not exist");
        _;
    }

    // Modifier to check if the caller is an authorized partner
    modifier onlyAuthorizedPartner(bytes32 operationId) {
        require(operations[operationId].exists, "Operation record does not exist");
        bool isAuthorized = operations[operationId].owner == msg.sender;
        if (!isAuthorized) {
            for (uint256 i = 0; i < operations[operationId].partners.length; i++) {
                if (operations[operationId].partners[i] == msg.sender) {
                    isAuthorized = true;
                    break;
                }
            }
        }
        require(isAuthorized, "Only authorized partners can perform this action");
        _;
    }

    /**
     * @dev Creates a new cyber operation record.
     * @param _operationName The name of the cyber operation.
     * @param _description The description of the operation.
     * @param _initiative The associated strategic initiative.
     * @param _classification The classification level (e.g., "Unclassified", "Secret").
     * @return operationId The unique ID of the created record.
     */
    function createOperation(
        string memory _operationName,
        string memory _description,
        StrategicInitiative _initiative,
        string memory _classification
    ) public returns (bytes32) {
        // Generate a unique ID for the operation record
        bytes32 operationId = keccak256(abi.encodePacked(_operationName, msg.sender, block.timestamp));
        
        // Ensure the record doesn't already exist
        require(!operations[operationId].exists, "Operation record with this ID already exists");

        // Initialize the operation record
        CyberOperation storage newOperation = operations[operationId];
        newOperation.operationName = _operationName;
        newOperation.description = _description;
        newOperation.initiative = _initiative;
        newOperation.classification = _classification;
        newOperation.owner = msg.sender;
        newOperation.exists = true;
        newOperation.partners.push(msg.sender); // Owner is an initial partner

        // Emit event for operation creation
        emit OperationCreated(operationId, _operationName, msg.sender, _initiative);

        return operationId;
    }

    /**
     * @dev Updates the core fields of an existing operation record.
     * @param _operationId The ID of the operation record to update.
     * @param _description The new description.
     * @param _classification The new classification level.
     */
    function updateOperation(
        bytes32 _operationId,
        string memory _description,
        string memory _classification
    ) public onlyOperationOwner(_operationId) {
        CyberOperation storage operation = operations[_operationId];
        operation.description = _description;
        operation.classification = _classification;

        // Emit event for operation update
        emit OperationUpdated(_operationId, operation.operationName, msg.sender);
    }

    /**
     * @dev Adds a security control to an operation record.
     * @param _operationId The ID of the operation record.
     * @param _controlKey The key of the security control (e.g., "SC-1").
     * @param _compliant Whether the control is compliant.
     */
    function addSecurityControl(
        bytes32 _operationId,
        string memory _controlKey,
        bool _compliant
    ) public onlyOperationOwner(_operationId) {
        operations[_operationId].securityControls[_controlKey] = _compliant;
        operations[_operationId].controlKeys.push(_controlKey);

        // Emit event for security control addition
        emit SecurityControlAdded(_operationId, _controlKey, _compliant);
    }

    /**
     * @dev Updates the compliance status of a security control.
     * @param _operationId The ID of the operation record.
     * @param _controlKey The key of the security control.
     * @param _compliant The new compliance status.
     */
    function updateSecurityControlStatus(
        bytes32 _operationId,
        string memory _controlKey,
        bool _compliant
    ) public onlyAuthorizedPartner(_operationId) {
        // Check if the control exists
        bool controlExists = false;
        for (uint256 i = 0; i < operations[_operationId].controlKeys.length; i++) {
            if (keccak256(abi.encodePacked(operations[_operationId].controlKeys[i])) == keccak256(abi.encodePacked(_controlKey))) {
                controlExists = true;
                break;
            }
        }
        require(controlExists, "Security control does not exist");

        operations[_operationId].securityControls[_controlKey] = _compliant;

        // Emit event for security control status update
        emit SecurityControlStatusUpdated(_operationId, _controlKey, _compliant);
    }

    /**
     * @dev Adds an authorized partner to an operation record.
     * @param _operationId The ID of the operation record.
     * @param _partner The address of the partner to authorize.
     */
    function addPartner(bytes32 _operationId, address _partner) public onlyOperationOwner(_operationId) {
        require(_partner != address(0), "Invalid partner address");
        // Check if partner is already authorized
        for (uint256 i = 0; i < operations[_operationId].partners.length; i++) {
            require(operations[_operationId].partners[i] != _partner, "Partner already authorized");
        }
        operations[_operationId].partners.push(_partner);

        // Emit event for partner addition
        emit PartnerAdded(_operationId, _partner);
    }

    /**
     * @dev Checks if all security controls for an operation are compliant.
     * @param _operationId The ID of the operation record.
     * @return Whether all security controls are compliant.
     */
    function isOperationCompliant(bytes32 _operationId) public view returns (bool) {
        require(operations[_operationId].exists, "Operation record does not exist");
        // Check each control in the controlKeys array
        for (uint256 i = 0; i < operations[_operationId].controlKeys.length; i++) {
            string memory key = operations[_operationId].controlKeys[i];
            if (!operations[_operationId].securityControls[key]) {
                return false;
            }
        }
        return true;
    }

    /**
     * @dev Retrieves the core fields of an operation record.
     * @param _operationId The ID of the operation record.
     * @return operationName The name of the operation.
     * @return description The description of the operation.
     * @return initiative The associated strategic initiative.
     * @return classification The classification level.
     * @return owner The owner of the record.
     */
    function getOperation(bytes32 _operationId)
        public
        view
        onlyAuthorizedPartner(_operationId)
        returns (
            string memory operationName,
            string memory description,
            StrategicInitiative initiative,
            string memory classification,
            address owner
        )
    {
        require(operations[_operationId].exists, "Operation record does not exist");
        CyberOperation storage operation = operations[_operationId];
        return (
            operation.operationName,
            operation.description,
            operation.initiative,
            operation.classification,
            operation.owner
        );
    }

    /**
     * @dev Retrieves the compliance status of a security control.
     * @param _operationId The ID of the operation record.
     * @param _controlKey The key of the security control.
     * @return The compliance status of the control.
     */
    function getSecurityControlStatus(bytes32 _operationId, string memory _controlKey)
        public
        view
        onlyAuthorizedPartner(_operationId)
        returns (bool)
    {
        require(operations[_operationId].exists, "Operation record does not exist");
        return operations[_operationId].securityControls[_controlKey];
    }

    /**
     * @dev Retrieves the list of security control keys for an operation record.
     * @param _operationId The ID of the operation record.
     * @return The array of control keys.
     */
    function getControlKeys(bytes32 _operationId)
        public
        view
        onlyAuthorizedPartner(_operationId)
        returns (string[] memory)
    {
        require(operations[_operationId].exists, "Operation record does not exist");
        return operations[_operationId].controlKeys;
    }

    /**
     * @dev Retrieves the list of authorized partners for an operation record.
     * @param _operationId The ID of the operation record.
     * @return The array of authorized partner addresses.
     */
    function getPartners(bytes32 _operationId)
        public
        view
        onlyOperationOwner(_operationId)
        returns (address[] memory)
    {
        require(operations[_operationId].exists, "Operation record does not exist");
        return operations[_operationId].partners;
    }
}