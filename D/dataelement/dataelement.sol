// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title DataElementRegistry
 * @notice
 *   Implements CNSSI 4009-2015 “Data Element” concept:
 *   a basic unit of information with a unique meaning and subcategories
 *   (data items) of distinct value.  Examples: gender, race, geographic location.
 *
 * Roles:
 *   • DEFAULT_ADMIN_ROLE: can add/remove editors, pause/unpause, and delete elements.
 *   • EDITOR_ROLE: may register or update data elements and their items.
 */
contract DataElementRegistry is AccessControl, Pausable {
    bytes32 public constant EDITOR_ROLE = keccak256("EDITOR_ROLE");

    struct DataItem {
        string  label;       // e.g. "Male", "Female", "Non-binary"
        string  description; // optional human‐readable description
        bool    exists;
    }

    struct DataElement {
        string         name;        // e.g. "Gender"
        string         definition;  // e.g. "A person’s gender identity"
        bool           exists;
        uint256[]      itemIds;     // keys into the items mapping
    }

    uint256 private _nextElementId = 1;
    uint256 private _nextItemId    = 1;

    // elementId => DataElement
    mapping(uint256 => DataElement) private _elements;
    // elementId => (itemId => DataItem)
    mapping(uint256 => mapping(uint256 => DataItem)) private _items;

    event ElementRegistered(uint256 indexed elementId, string name, string definition);
    event ElementUpdated   (uint256 indexed elementId, string newName, string newDefinition);
    event ElementRemoved   (uint256 indexed elementId);

    event ItemRegistered   (uint256 indexed elementId, uint256 indexed itemId, string label, string description);
    event ItemUpdated      (uint256 indexed elementId, uint256 indexed itemId, string newLabel, string newDescription);
    event ItemRemoved      (uint256 indexed elementId, uint256 indexed itemId);

    modifier onlyEditor() {
        require(hasRole(EDITOR_ROLE, msg.sender), "DataElementRegistry: not an editor");
        _;
    }

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    /// @notice Grant EDITOR_ROLE to an account
    function addEditor(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(EDITOR_ROLE, account);
    }

    /// @notice Revoke EDITOR_ROLE from an account
    function removeEditor(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(EDITOR_ROLE, account);
    }

    /// @notice Pause registry operations
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause registry operations
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @notice Register a new data element
    function registerElement(string calldata name, string calldata definition)
        external
        whenNotPaused
        onlyEditor
        returns (uint256 elementId)
    {
        require(bytes(name).length > 0, "Name required");
        elementId = _nextElementId++;
        DataElement storage e = _elements[elementId];
        e.name       = name;
        e.definition = definition;
        e.exists     = true;
        emit ElementRegistered(elementId, name, definition);
    }

    /// @notice Update an existing data element
    function updateElement(uint256 elementId, string calldata newName, string calldata newDefinition)
        external
        whenNotPaused
        onlyEditor
    {
        DataElement storage e = _elements[elementId];
        require(e.exists, "Element not found");
        e.name       = newName;
        e.definition = newDefinition;
        emit ElementUpdated(elementId, newName, newDefinition);
    }

    /// @notice Remove a data element and all its items
    function removeElement(uint256 elementId)
        external
        whenNotPaused
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        DataElement storage e = _elements[elementId];
        require(e.exists, "Element not found");
        // delete items
        for(uint256 i = 0; i < e.itemIds.length; i++){
            uint256 itemId = e.itemIds[i];
            delete _items[elementId][itemId];
            emit ItemRemoved(elementId, itemId);
        }
        delete _elements[elementId];
        emit ElementRemoved(elementId);
    }

    /// @notice Register a new data item under a given element
    function registerItem(uint256 elementId, string calldata label, string calldata description)
        external
        whenNotPaused
        onlyEditor
        returns (uint256 itemId)
    {
        DataElement storage e = _elements[elementId];
        require(e.exists, "Element not found");
        require(bytes(label).length > 0, "Label required");

        itemId = _nextItemId++;
        DataItem storage it = _items[elementId][itemId];
        it.label       = label;
        it.description = description;
        it.exists      = true;

        e.itemIds.push(itemId);
        emit ItemRegistered(elementId, itemId, label, description);
    }

    /// @notice Update an existing data item
    function updateItem(uint256 elementId, uint256 itemId, string calldata newLabel, string calldata newDescription)
        external
        whenNotPaused
        onlyEditor
    {
        DataItem storage it = _items[elementId][itemId];
        require(it.exists, "Item not found");
        it.label       = newLabel;
        it.description = newDescription;
        emit ItemUpdated(elementId, itemId, newLabel, newDescription);
    }

    /// @notice Remove a data item from an element
    function removeItem(uint256 elementId, uint256 itemId)
        external
        whenNotPaused
        onlyEditor
    {
        DataElement storage e = _elements[elementId];
        DataItem    storage it = _items[elementId][itemId];
        require(e.exists && it.exists, "Element or item not found");

        // remove from itemIds array
        uint256 len = e.itemIds.length;
        for(uint256 i = 0; i < len; i++){
            if(e.itemIds[i] == itemId){
                e.itemIds[i] = e.itemIds[len-1];
                e.itemIds.pop();
                break;
            }
        }

        delete _items[elementId][itemId];
        emit ItemRemoved(elementId, itemId);
    }

    /// @notice Get metadata of a data element
    function getElement(uint256 elementId)
        external
        view
        returns (string memory name, string memory definition, uint256[] memory itemIds)
    {
        DataElement storage e = _elements[elementId];
        require(e.exists, "Element not found");
        return (e.name, e.definition, e.itemIds);
    }

    /// @notice Get a data item’s details
    function getItem(uint256 elementId, uint256 itemId)
        external
        view
        returns (string memory label, string memory description)
    {
        DataItem storage it = _items[elementId][itemId];
        require(it.exists, "Item not found");
        return (it.label, it.description);
    }
}
