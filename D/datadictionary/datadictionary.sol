// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title DataDictionary
 * @notice
 *   A registry of data dictionary entries, as defined in NIST SP 800-188:
 *   a collection of entries that allows lookup by entity identifier.
 *
 * Roles:
 *   • DEFAULT_ADMIN_ROLE: can pause/unpause, add/remove writers, and delete entries.
 *   • WRITER_ROLE: may register or update entries.
 *
 * Each entry:
 *   • entityId: unique string identifier
 *   • definition: textual description or JSON schema fragment
 *   • writer: address that created or last updated the entry
 */
contract DataDictionary is AccessControl, Pausable {
    bytes32 public constant WRITER_ROLE = keccak256("WRITER_ROLE");

    struct Entry {
        string definition;
        address writer;
        bool exists;
    }

    // entityId → Entry
    mapping(string => Entry) private _entries;
    // list of all entityIds
    string[] private _entityIds;

    event WriterAdded(address indexed account);
    event WriterRemoved(address indexed account);
    event EntryRegistered(string indexed entityId, address indexed writer, string definition);
    event EntryUpdated(string indexed entityId, address indexed writer, string newDefinition);
    event EntryRemoved(string indexed entityId);

    modifier onlyWriter() {
        require(hasRole(WRITER_ROLE, msg.sender), "DataDictionary: not a writer");
        _;
    }

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    /// @notice Grant the WRITER_ROLE to an account
    function addWriter(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(WRITER_ROLE, account);
        emit WriterAdded(account);
    }

    /// @notice Revoke the WRITER_ROLE from an account
    function removeWriter(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(WRITER_ROLE, account);
        emit WriterRemoved(account);
    }

    /// @notice Pause all dictionary operations
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause dictionary operations
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /**
     * @notice Register a new data dictionary entry.
     * @param entityId   Unique identifier for the data entity.
     * @param definition Textual definition or JSON schema for the entity.
     */
    function registerEntry(string calldata entityId, string calldata definition)
        external
        whenNotPaused
        onlyWriter
    {
        require(!_entries[entityId].exists, "DataDictionary: entity already exists");
        _entries[entityId] = Entry({
            definition: definition,
            writer:     msg.sender,
            exists:     true
        });
        _entityIds.push(entityId);
        emit EntryRegistered(entityId, msg.sender, definition);
    }

    /**
     * @notice Update an existing data dictionary entry.
     * @param entityId     Identifier of the entry to update.
     * @param newDefinition New definition or schema.
     */
    function updateEntry(string calldata entityId, string calldata newDefinition)
        external
        whenNotPaused
        onlyWriter
    {
        Entry storage e = _entries[entityId];
        require(e.exists, "DataDictionary: entity not found");
        e.definition = newDefinition;
        e.writer     = msg.sender;
        emit EntryUpdated(entityId, msg.sender, newDefinition);
    }

    /**
     * @notice Remove a data dictionary entry.
     * @param entityId Identifier of the entry to remove.
     */
    function removeEntry(string calldata entityId)
        external
        whenNotPaused
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        Entry storage e = _entries[entityId];
        require(e.exists, "DataDictionary: entity not found");
        delete _entries[entityId];
        // remove from entityIds array
        uint256 n = _entityIds.length;
        for (uint256 i = 0; i < n; i++) {
            if (keccak256(bytes(_entityIds[i])) == keccak256(bytes(entityId))) {
                _entityIds[i] = _entityIds[n - 1];
                _entityIds.pop();
                break;
            }
        }
        emit EntryRemoved(entityId);
    }

    /**
     * @notice Retrieve the definition and writer for a given entityId.
     * @param entityId Identifier of the entry.
     * @return definition The stored definition.
     * @return writer     Address that last wrote the entry.
     */
    function getEntry(string calldata entityId)
        external
        view
        returns (string memory definition, address writer)
    {
        Entry storage e = _entries[entityId];
        require(e.exists, "DataDictionary: entity not found");
        return (e.definition, e.writer);
    }

    /**
     * @notice List all registered entity identifiers.
     * @return entityIds Array of all entityIds in the dictionary.
     */
    function listEntityIds() external view returns (string[] memory entityIds) {
        return _entityIds;
    }
}
