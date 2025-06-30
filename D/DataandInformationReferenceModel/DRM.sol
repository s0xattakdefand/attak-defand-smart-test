// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title DataAndInformationReferenceModel
 * @notice
 *   Implements a simple on-chain “Data and Information Reference Model” allowing
 *   administrators to register data entities, define their attributes, and
 *   specify relationships between entities.  Useful for standardized metadata
 *   registries, data catalogs, and semantic data modeling.
 *
 * Roles:
 *   • DEFAULT_ADMIN_ROLE: can add/remove Modelers and pause/unpause the registry.
 *   • MODELER_ROLE: may register entities, attributes, and relationships.
 *
 * Data Structures:
 *   • Entity: unique id, name, version, schemaURI, exists flag.
 *   • Attribute: belongs to an Entity; name, dataType, metadataURI.
 *   • Relationship: directed link between two Entities with a type and metadataURI.
 */
contract DataAndInformationReferenceModel is AccessControl, Pausable {
    bytes32 public constant MODELER_ROLE = keccak256("MODELER_ROLE");

    struct Entity {
        string  name;
        uint256 version;
        string  schemaURI;  // pointer to detailed schema JSON/YAML
        bool    exists;
    }

    struct Attribute {
        uint256 entityId;
        string  name;
        string  dataType;    // e.g. "string", "uint256", "address"
        string  metadataURI; // pointer to attribute description
    }

    struct Relationship {
        uint256 fromEntity;
        uint256 toEntity;
        string  relationType;  // e.g. "one-to-many", "belongs-to"
        string  metadataURI;   // pointer to relationship semantics
    }

    uint256 private _nextEntityId = 1;
    uint256 private _nextAttrId   = 1;
    uint256 private _nextRelId    = 1;

    mapping(uint256 => Entity)              private _entities;
    mapping(uint256 => Attribute)           private _attributes;
    mapping(uint256 => Relationship)        private _relationships;

    // for lookup
    mapping(uint256 => uint256[])           private _entityAttrs;
    mapping(uint256 => uint256[])           private _outgoingRels;
    mapping(uint256 => uint256[])           private _incomingRels;

    event ModelerAdded(address indexed account);
    event ModelerRemoved(address indexed account);

    event EntityRegistered(uint256 indexed entityId, string name, uint256 version, string schemaURI);
    event EntityUpdated   (uint256 indexed entityId, uint256 newVersion, string newSchemaURI);

    event AttributeRegistered(uint256 indexed attrId, uint256 indexed entityId, string name, string dataType, string metadataURI);

    event RelationshipRegistered(
        uint256 indexed relId,
        uint256 indexed fromEntity,
        uint256 indexed toEntity,
        string relationType,
        string metadataURI
    );

    modifier onlyModeler() {
        require(hasRole(MODELER_ROLE, msg.sender), "DIRM: not a modeler");
        _;
    }

    constructor(address admin) {
        // grant admin roles
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(MODELER_ROLE, admin);
    }

    /// @notice Grant MODELER_ROLE to an account
    function addModeler(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(MODELER_ROLE, account);
        emit ModelerAdded(account);
    }

    /// @notice Revoke MODELER_ROLE from an account
    function removeModeler(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(MODELER_ROLE, account);
        emit ModelerRemoved(account);
    }

    /// @notice Pause registry actions
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause registry actions
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @notice Register a new data entity
    function registerEntity(string calldata name, uint256 version, string calldata schemaURI)
        external
        whenNotPaused
        onlyModeler
        returns (uint256 entityId)
    {
        require(bytes(name).length > 0, "DIRM: name empty");
        entityId = _nextEntityId++;
        _entities[entityId] = Entity({
            name:      name,
            version:   version,
            schemaURI: schemaURI,
            exists:    true
        });
        emit EntityRegistered(entityId, name, version, schemaURI);
    }

    /// @notice Update an existing entity’s version and schema
    function updateEntity(uint256 entityId, uint256 newVersion, string calldata newSchemaURI)
        external
        whenNotPaused
        onlyModeler
    {
        Entity storage e = _entities[entityId];
        require(e.exists, "DIRM: unknown entity");
        e.version   = newVersion;
        e.schemaURI = newSchemaURI;
        emit EntityUpdated(entityId, newVersion, newSchemaURI);
    }

    /// @notice Register an attribute under a specific entity
    function registerAttribute(
        uint256 entityId,
        string calldata name,
        string calldata dataType,
        string calldata metadataURI
    ) external whenNotPaused onlyModeler returns (uint256 attrId) {
        require(_entities[entityId].exists, "DIRM: unknown entity");
        require(bytes(name).length > 0, "DIRM: attr name empty");
        attrId = _nextAttrId++;
        _attributes[attrId] = Attribute({
            entityId:    entityId,
            name:        name,
            dataType:    dataType,
            metadataURI: metadataURI
        });
        _entityAttrs[entityId].push(attrId);
        emit AttributeRegistered(attrId, entityId, name, dataType, metadataURI);
    }

    /// @notice Register a relationship between two entities
    function registerRelationship(
        uint256 fromEntity,
        uint256 toEntity,
        string calldata relationType,
        string calldata metadataURI
    ) external whenNotPaused onlyModeler returns (uint256 relId) {
        require(_entities[fromEntity].exists && _entities[toEntity].exists, "DIRM: unknown entity");
        relId = _nextRelId++;
        _relationships[relId] = Relationship({
            fromEntity:   fromEntity,
            toEntity:     toEntity,
            relationType: relationType,
            metadataURI:  metadataURI
        });
        _outgoingRels[fromEntity].push(relId);
        _incomingRels[toEntity].push(relId);
        emit RelationshipRegistered(relId, fromEntity, toEntity, relationType, metadataURI);
    }

    /// @notice Fetch entity details
    function getEntity(uint256 entityId)
        external
        view
        returns (string memory name, uint256 version, string memory schemaURI)
    {
        Entity storage e = _entities[entityId];
        require(e.exists, "DIRM: unknown entity");
        return (e.name, e.version, e.schemaURI);
    }

    /// @notice List all attribute IDs for an entity
    function listAttributes(uint256 entityId) external view returns (uint256[] memory) {
        return _entityAttrs[entityId];
    }

    /// @notice Fetch attribute details
    function getAttribute(uint256 attrId)
        external
        view
        returns (uint256 entityId, string memory name, string memory dataType, string memory metadataURI)
    {
        Attribute storage a = _attributes[attrId];
        require(_entities[a.entityId].exists, "DIRM: unknown attribute");
        return (a.entityId, a.name, a.dataType, a.metadataURI);
    }

    /// @notice List outgoing relationship IDs for an entity
    function listOutgoingRelationships(uint256 entityId) external view returns (uint256[] memory) {
        return _outgoingRels[entityId];
    }

    /// @notice List incoming relationship IDs for an entity
    function listIncomingRelationships(uint256 entityId) external view returns (uint256[] memory) {
        return _incomingRels[entityId];
    }

    /// @notice Fetch relationship details
    function getRelationship(uint256 relId)
        external
        view
        returns (uint256 fromEntity, uint256 toEntity, string memory relationType, string memory metadataURI)
    {
        Relationship storage r = _relationships[relId];
        require(_entities[r.fromEntity].exists && _entities[r.toEntity].exists, "DIRM: unknown relationship");
        return (r.fromEntity, r.toEntity, r.relationType, r.metadataURI);
    }
}
