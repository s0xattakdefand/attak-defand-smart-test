// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

/**
 * @title DefinitionOfDone
 * @dev A smart contract for managing Definitions of Done (DoD) on the Ethereum blockchain.
 * Allows users to create, update, and verify DoD criteria with access control.
 * THIS IS AN EXAMPLE CONTRACT THAT USES UN-AUDITED CODE.
 * DO NOT USE THIS CODE IN PRODUCTION.
 */
contract DefinitionOfDone {
    // Struct to represent a Definition of Done
    struct DoD {
        string name; // Name of the DoD (e.g., "Sprint 1 DoD")
        string description; // Description of the DoD
        mapping(string => bool) criteria; // Criteria and their required/completion status
        string[] criterionKeys; // Array to track defined criterion keys
        address owner; // Owner of the DoD
        bool exists; // Flag to check if DoD exists
    }

    // Mapping to store DoDs by their unique ID
    mapping(bytes32 => DoD) public doDs;

    // Event emitted when a new DoD is created
    event DoDCreated(bytes32 indexed doDId, string name, address indexed owner);
    // Event emitted when a DoD is updated
    event DoDUpdated(bytes32 indexed doDId, string name, address indexed owner);
    // Event emitted when a criterion is added to a DoD
    event CriterionAdded(bytes32 indexed doDId, string criterionKey, bool required);
    // Event emitted when a criterion's status is updated
    event CriterionStatusUpdated(bytes32 indexed doDId, string criterionKey, bool completed);

    // Modifier to check if the caller is the owner of the DoD
    modifier onlyDoDOwner(bytes32 doDId) {
        require(doDs[doDId].owner == msg.sender, "Only the DoD owner can perform this action");
        require(doDs[doDId].exists, "DoD does not exist");
        _;
    }

    /**
     * @dev Creates a new Definition of Done.
     * @param _name The name of the DoD.
     * @param _description A description of the DoD.
     * @return doDId The unique ID of the created DoD.
     */
    function createDoD(string memory _name, string memory _description) public returns (bytes32) {
        // Generate a unique ID for the DoD using a hash of the name and sender
        bytes32 doDId = keccak256(abi.encodePacked(_name, msg.sender, block.timestamp));
        
        // Ensure the DoD doesn't already exist
        require(!doDs[doDId].exists, "DoD with this ID already exists");

        // Initialize the DoD
        DoD storage newDoD = doDs[doDId];
        newDoD.name = _name;
        newDoD.description = _description;
        newDoD.owner = msg.sender;
        newDoD.exists = true;

        // Emit event for DoD creation
        emit DoDCreated(doDId, _name, msg.sender);

        return doDId;
    }

    /**
     * @dev Updates the description of an existing DoD.
     * @param _doDId The ID of the DoD to update.
     * @param _newDescription The new description for the DoD.
     */
    function updateDoDDescription(bytes32 _doDId, string memory _newDescription) public onlyDoDOwner(_doDId) {
        doDs[_doDId].description = _newDescription;

        // Emit event for DoD update
        emit DoDUpdated(_doDId, doDs[_doDId].name, msg.sender);
    }

    /**
     * @dev Adds a criterion to a DoD.
     * @param _doDId The ID of the DoD.
     * @param _criterionKey The name of the criterion (e.g., "CodeReview").
     * @param _required Whether the criterion is required to consider the DoD complete.
     */
    function addCriterion(bytes32 _doDId, string memory _criterionKey, bool _required) public onlyDoDOwner(_doDId) {
        doDs[_doDId].criteria[_criterionKey] = _required;
        doDs[_doDId].criterionKeys.push(_criterionKey);

        // Emit event for criterion addition
        emit CriterionAdded(_doDId, _criterionKey, _required);
    }

    /**
     * @dev Updates the completion status of a criterion.
     * @param _doDId The ID of the DoD.
     * @param _criterionKey The name of the criterion.
     * @param _completed Whether the criterion has been completed.
     */
    function updateCriterionStatus(bytes32 _doDId, string memory _criterionKey, bool _completed) public onlyDoDOwner(_doDId) {
        // Check if the criterion exists by searching the criterionKeys array
        bool criterionExists = false;
        for (uint256 i = 0; i < doDs[_doDId].criterionKeys.length; i++) {
            if (keccak256(abi.encodePacked(doDs[_doDId].criterionKeys[i])) == keccak256(abi.encodePacked(_criterionKey))) {
                criterionExists = true;
                break;
            }
        }
        require(criterionExists, "Criterion does not exist");

        doDs[_doDId].criteria[_criterionKey] = _completed;

        // Emit event for criterion status update
        emit CriterionStatusUpdated(_doDId, _criterionKey, _completed);
    }

    /**
     * @dev Checks if all required criteria for a DoD are met.
     * @param _doDId The ID of the DoD.
     * @return Whether the DoD is considered complete.
     */
    function isDoDComplete(bytes32 _doDId) public view returns (bool) {
        require(doDs[_doDId].exists, "DoD does not exist");
        // Check each criterion in the criterionKeys array
        for (uint256 i = 0; i < doDs[_doDId].criterionKeys.length; i++) {
            string memory key = doDs[_doDId].criterionKeys[i];
            // If the criterion is required (true) but not completed (false), return false
            if (doDs[_doDId].criteria[key] && !doDs[_doDId].criteria[key]) {
                return false;
            }
        }
        return true;
    }

    /**
     * @dev Retrieves the details of a DoD.
     * @param _doDId The ID of the DoD.
     * @return name The name of the DoD.
     * @return description The description of the DoD.
     * @return owner The owner of the DoD.
     */
    function getDoD(bytes32 _doDId) public view returns (string memory name, string memory description, address owner) {
        require(doDs[_doDId].exists, "DoD does not exist");
        DoD storage doD = doDs[_doDId];
        return (doD.name, doD.description, doD.owner);
    }

    /**
     * @dev Retrieves the status of a specific criterion in a DoD.
     * @param _doDId The ID of the DoD.
     * @param _criterionKey The name of the criterion.
     * @return The status of the criterion.
     */
    function getCriterionStatus(bytes32 _doDId, string memory _criterionKey) public view returns (bool) {
        require(doDs[_doDId].exists, "DoD does not exist");
        return doDs[_doDId].criteria[_criterionKey];
    }

    /**
     * @dev Retrieves the list of criterion keys for a DoD.
     * @param _doDId The ID of the DoD.
     * @return The array of criterion keys.
     */
    function getCriterionKeys(bytes32 _doDId) public view returns (string[] memory) {
        require(doDs[_doDId].exists, "DoD does not exist");
        return doDs[_doDId].criterionKeys;
    }
}
