// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

/**
 * @title DocumentTypeDefinition
 * @dev A smart contract for managing Document Type Definitions (DTDs) on the Ethereum blockchain.
 * Allows users to create, update, and retrieve document type definitions with access control.
 * THIS IS AN EXAMPLE CONTRACT THAT USES UN-AUDITED CODE.
 * DO NOT USE THIS CODE IN PRODUCTION.
 */
contract DocumentTypeDefinition {
    // Struct to represent a Document Type Definition
    struct DTD {
        string name; // Name of the document type (e.g., "Invoice")
        string description; // Description of the document type
        mapping(string => string) elements; // Key-value pairs for allowed elements/rules (e.g., "tag" => "type")
        address owner; // Owner of the DTD
        bool exists; // Flag to check if DTD exists
    }

    // Mapping to store DTDs by their unique ID
    mapping(bytes32 => DTD) public dtds;

    // Event emitted when a new DTD is created
    event DTDCreated(bytes32 indexed dtdId, string name, address indexed owner);
    // Event emitted when a DTD is updated
    event DTDUpdated(bytes32 indexed dtdId, string name, address indexed owner);
    // Event emitted when an element is added to a DTD
    event ElementAdded(bytes32 indexed dtdId, string elementKey, string elementValue);

    // Modifier to check if the caller is the owner of the DTD
    modifier onlyDTDOwner(bytes32 dtdId) {
        require(dtds[dtdId].owner == msg.sender, "Only the DTD owner can perform this action");
        require(dtds[dtdId].exists, "DTD does not exist");
        _;
    }

    /**
     * @dev Creates a new Document Type Definition.
     * @param _name The name of the DTD.
     * @param _description A description of the DTD.
     * @return dtdId The unique ID of the created DTD.
     */
    function createDTD(string memory _name, string memory _description) public returns (bytes32) {
        // Generate a unique ID for the DTD using a hash of the name and sender
        bytes32 dtdId = keccak256(abi.encodePacked(_name, msg.sender, block.timestamp));
        
        // Ensure the DTD doesn't already exist
        require(!dtds[dtdId].exists, "DTD with this ID already exists");

        // Initialize the DTD
        DTD storage newDTD = dtds[dtdId];
        newDTD.name = _name;
        newDTD.description = _description;
        newDTD.owner = msg.sender;
        newDTD.exists = true;

        // Emit event for DTD creation
        emit DTDCreated(dtdId, _name, msg.sender);

        return dtdId;
    }

    /**
     * @dev Updates the description of an existing DTD.
     * @param _dtdId The ID of the DTD to update.
     * @param _newDescription The new description for the DTD.
     */
    function updateDTDDescription(bytes32 _dtdId, string memory _newDescription) public onlyDTDOwner(_dtdId) {
        dtds[_dtdId].description = _newDescription;

        // Emit event for DTD update
        emit DTDUpdated(_dtdId, dtds[_dtdId].name, msg.sender);
    }

    /**
     * @dev Adds an element (key-value pair) to a DTD.
     * @param _dtdId The ID of the DTD.
     * @param _elementKey The key of the element (e.g., "title").
     * @param _elementValue The value or type of the element (e.g., "string").
     */
    function addDTDElement(bytes32 _dtdId, string memory _elementKey, string memory _elementValue) public onlyDTDOwner(_dtdId) {
        dtds[_dtdId].elements[_elementKey] = _elementValue;

        // Emit event for element addition
        emit ElementAdded(_dtdId, _elementKey, _elementValue);
    }

    /**
     * @dev Retrieves the details of a DTD.
     * @param _dtdId The ID of the DTD.
     * @return name The name of the DTD.
     * @return description The description of the DTD.
     * @return owner The owner of the DTD.
     */
    function getDTD(bytes32 _dtdId) public view returns (string memory name, string memory description, address owner) {
        require(dtds[_dtdId].exists, "DTD does not exist");
        DTD storage dtd = dtds[_dtdId];
        return (dtd.name, dtd.description, dtd.owner);
    }

    /**
     * @dev Retrieves the value of a specific element in a DTD.
     * @param _dtdId The ID of the DTD.
     * @param _elementKey The key of the element.
     * @return The value of the element.
     */
    function getDTDElement(bytes32 _dtdId, string memory _elementKey) public view returns (string memory) {
        require(dtds[_dtdId].exists, "DTD does not exist");
        return dtds[_dtdId].elements[_elementKey];
    }
}
