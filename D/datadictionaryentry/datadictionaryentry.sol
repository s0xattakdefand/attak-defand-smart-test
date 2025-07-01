// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title EntityTypeRegistry
 * @notice
 *   Implements a registry of “entity types” per NIST SP 800-188:
 *   each entry includes an unambiguous identifier, a term, and a definition.
 *
 * Roles:
 *   • DEFAULT_ADMIN_ROLE: can pause/unpause, add/remove editors, and delete types.
 *   • EDITOR_ROLE: may register or update entity types.
 *
 * Each EntityType:
 *   • id         – unique string identifier
 *   • term       – human‐readable term
 *   • definition – full definition text
 */
contract EntityTypeRegistry is AccessControl, Pausable {
    bytes32 public constant EDITOR_ROLE = keccak256("EDITOR_ROLE");

    struct EntityType {
        string term;
        string definition;
        address editor;
        bool    exists;
    }

    // id → EntityType
    mapping(string => EntityType) private _types;
    // list of all ids for enumeration
    string[] private _ids;

    event EditorAdded(address indexed account);
    event EditorRemoved(address indexed account);
    event EntityTypeRegistered(string indexed id, address indexed editor, string term, string definition);
    event EntityTypeUpdated(string indexed id, address indexed editor, string newTerm, string newDefinition);
    event EntityTypeRemoved(string indexed id);

    modifier onlyEditor() {
        require(hasRole(EDITOR_ROLE, msg.sender), "EntityTypeRegistry: not an editor");
        _;
    }

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    /// @notice Grant EDITOR_ROLE to an account
    function addEditor(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(EDITOR_ROLE, account);
        emit EditorAdded(account);
    }

    /// @notice Revoke EDITOR_ROLE from an account
    function removeEditor(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(EDITOR_ROLE, account);
        emit EditorRemoved(account);
    }

    /// @notice Pause registry operations
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause registry operations
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /**
     * @notice Register a new entity type.
     * @param id         Unique identifier (e.g. "UserAccount", "Transaction").
     * @param term       Human‐readable term.
     * @param definition Full textual definition.
     */
    function registerEntityType(
        string calldata id,
        string calldata term,
        string calldata definition
    )
        external
        whenNotPaused
        onlyEditor
    {
        require(bytes(id).length > 0, "EntityTypeRegistry: id required");
        require(!_types[id].exists, "EntityTypeRegistry: id exists");
        _types[id] = EntityType({
            term:       term,
            definition: definition,
            editor:     msg.sender,
            exists:     true
        });
        _ids.push(id);
        emit EntityTypeRegistered(id, msg.sender, term, definition);
    }

    /**
     * @notice Update an existing entity type.
     * @param id            Identifier of the entity type.
     * @param newTerm       New term.
     * @param newDefinition New definition.
     */
    function updateEntityType(
        string calldata id,
        string calldata newTerm,
        string calldata newDefinition
    )
        external
        whenNotPaused
        onlyEditor
    {
        EntityType storage et = _types[id];
        require(et.exists, "EntityTypeRegistry: not found");
        et.term       = newTerm;
        et.definition = newDefinition;
        et.editor     = msg.sender;
        emit EntityTypeUpdated(id, msg.sender, newTerm, newDefinition);
    }

    /**
     * @notice Remove an entity type.
     * @param id Identifier of the entity type to remove.
     */
    function removeEntityType(string calldata id)
        external
        whenNotPaused
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        EntityType storage et = _types[id];
        require(et.exists, "EntityTypeRegistry: not found");
        delete _types[id];
        // remove from _ids array
        for (uint i = 0; i < _ids.length; i++) {
            if (keccak256(bytes(_ids[i])) == keccak256(bytes(id))) {
                _ids[i] = _ids[_ids.length - 1];
                _ids.pop();
                break;
            }
        }
        emit EntityTypeRemoved(id);
    }

    /**
     * @notice Retrieve an entity type’s details.
     * @param id Identifier of the entity type.
     * @return term       Human‐readable term.
     * @return definition Full textual definition.
     * @return editor     Address that last edited it.
     */
    function getEntityType(string calldata id)
        external
        view
        returns (
            string memory term,
            string memory definition,
            address editor
        )
    {
        EntityType storage et = _types[id];
        require(et.exists, "EntityTypeRegistry: not found");
        return (et.term, et.definition, et.editor);
    }

    /**
     * @notice List all registered entity type identifiers.
     * @return ids Array of all entity type IDs.
     */
    function listEntityTypeIds() external view returns (string[] memory ids) {
        return _ids;
    }
}
