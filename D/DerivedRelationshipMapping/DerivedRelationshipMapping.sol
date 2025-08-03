// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// DerivedRelationshipMapping contract for managing derived relationships and data access
contract DerivedRelationshipMapping {
    // Contract owner (e.g., Agency Identity Management Office)
    address public immutable owner;

    // Structure to store an entity (e.g., personnel, contractor, device)
    struct Entity {
        bytes32 entityId; // Unique identifier for the entity
        address entityAddress; // Address of the entity
        string entityType; // Type of entity (e.g., Personnel, Contractor, Device)
        bytes32 dataHash; // Hash of entity details (using keccak256)
        string metadataURI; // Off-chain URI for detailed metadata (e.g., IPFS link)
        uint256 registrationTimestamp; // Timestamp of entity registration
        EntityStatus status; // Status of the entity
        address registrar; // Address of the entity registering the entity
    }

    // Structure to store a derived relationship
    struct Relationship {
        bytes32 relationshipId; // Unique identifier for the relationship
        bytes32 parentEntityId; // ID of the parent entity (e.g., primary PIV credential)
        bytes32 childEntityId; // ID of the child entity (e.g., derived credential, personnel)
        string relationshipType; // Type of relationship (e.g., Credential-to-Personnel, Contractor-to-Agency)
        bytes32 dataHash; // Hash of relationship details (using keccak256)
        string metadataURI; // Off-chain URI for relationship details
        uint256 creationTimestamp; // Timestamp of relationship creation
        uint256 terminationTimestamp; // Timestamp of relationship termination (0 if active)
        RelationshipStatus status; // Status of the relationship
        address creator; // Address of the entity creating/terminating the relationship
    }

    // Structure to store data access permission
    struct DataAccessPermission {
        bytes32 permissionId; // Unique identifier for the permission
        bytes32 entityId; // ID of the entity with access
        bytes32 dataId; // Hashed identifier for sensitive data (e.g., CUI)
        string metadataURI; // Off-chain URI for permission details
        uint256 timestamp; // Timestamp of permission grant
        uint256 revocationTimestamp; // Timestamp of permission revocation (0 if active)
        PermissionStatus status; // Status of the permission
        address reviewer; // Address of the entity granting/revoking permission
    }

    // Enum for entity status
    enum EntityStatus { Pending, Registered, Deregistered }

    // Enum for relationship status
    enum RelationshipStatus { Pending, Active, Terminated }

    // Enum for data access permission status
    enum PermissionStatus { Pending, Granted, Revoked }

    // Structure to store submission metadata for rate limiting
    struct SubmissionInfo {
        uint256 lastSubmissionTimestamp; // Timestamp of last submission
        uint256 submissionCount; // Number of submissions in current window
    }

    // Mapping to store entities by entity ID
    mapping(bytes32 => Entity) public entities;

    // Mapping to store relationships by relationship ID
    mapping(bytes32 => Relationship) public relationships;

    // Mapping to store data access permissions by permission ID
    mapping(bytes32 => DataAccessPermission) public permissions;

    // Mapping to store authorized registrars (e.g., agency officials)
    mapping(address => bool) public authorizedRegistrars;

    // Mapping to store submission metadata for rate limiting
    mapping(address => SubmissionInfo) public submissionInfo;

    // Rate limit parameters to prevent DoS
    uint256 public constant SUBMISSION_WINDOW = 1 hours; // Time window for rate limiting
    uint256 public constant MAX_SUBMISSIONS_PER_WINDOW = 5; // Max submissions per window
    uint256 public constant MIN_SUBMISSION_INTERVAL = 10 seconds; // Minimum time between submissions

    // Event emitted when an entity is submitted
    event EntitySubmitted(
        bytes32 indexed entityId,
        address indexed entityAddress,
        string entityType,
        bytes32 dataHash,
        string metadataURI,
        uint256 timestamp,
        address indexed registrar
    );

    // Event emitted when an entity is processed (registered or deregistered)
    event EntityProcessed(
        bytes32 indexed entityId,
        EntityStatus status,
        address indexed registrar,
        uint256 timestamp,
        string reason
    );

    // Event emitted when a relationship is submitted
    event RelationshipSubmitted(
        bytes32 indexed relationshipId,
        bytes32 indexed parentEntityId,
        bytes32 indexed childEntityId,
        string relationshipType,
        bytes32 dataHash,
        string metadataURI,
        uint256 timestamp,
        address creator
    );

    // Event emitted when a relationship is processed (activated or terminated)
    event RelationshipProcessed(
        bytes32 indexed relationshipId,
        RelationshipStatus status,
        address indexed creator,
        uint256 timestamp,
        string reason
    );

    // Event emitted when a data access permission is submitted
    event PermissionSubmitted(
        bytes32 indexed permissionId,
        bytes32 indexed entityId,
        bytes32 dataId,
        string metadataURI,
        uint256 timestamp,
        address indexed reviewer
    );

    // Event emitted when a data access permission is processed (granted or revoked)
    event PermissionProcessed(
        bytes32 indexed permissionId,
        PermissionStatus status,
        address indexed reviewer,
        uint256 timestamp,
        string reason
    );

    // Event emitted when a registrar is authorized or deauthorized
    event RegistrarAuthorizationUpdated(address indexed registrar, bool authorized, uint256 timestamp);

    // Event emitted when rate limit is triggered
    event RateLimitTriggered(address indexed entity, uint256 timestamp);

    // Modifier to restrict functions to the contract owner
    modifier onlyOwner() {
        if (msg.sender != owner) {
            revert("Only owner can call this function");
        }
        _;
    }

    // Modifier to restrict functions to authorized registrars
    modifier onlyAuthorizedRegistrar() {
        if (!authorizedRegistrars[msg.sender]) {
            revert("Only authorized registrars can call this function");
        }
        _;
    }

    // Modifier to check if an entity is pending
    modifier entityPending(bytes32 entityId) {
        if (entities[entityId].status != EntityStatus.Pending) {
            revert("Entity not pending or does not exist");
        }
        _;
    }

    // Modifier to check if a relationship is pending
    modifier relationshipPending(bytes32 relationshipId) {
        if (relationships[relationshipId].status != RelationshipStatus.Pending) {
            revert("Relationship not pending or does not exist");
        }
        _;
    }

    // Modifier to check if a permission is pending
    modifier permissionPending(bytes32 permissionId) {
        if (permissions[permissionId].status != PermissionStatus.Pending) {
            revert("Permission not pending or does not exist");
        }
        _;
    }

    // Constructor to set the immutable owner
    constructor() {
        owner = msg.sender;
        authorizedRegistrars[msg.sender] = true; // Owner is authorized by default
    }

    // Function to submit an entity for registration with rate limiting
    function submitEntity(
        bytes32 entityId,
        address entityAddress,
        string calldata entityType,
        bytes32 dataHash,
        string calldata metadataURI
    ) external onlyAuthorizedRegistrar {
        if (entities[entityId].status != EntityStatus.Pending) {
            revert("Entity ID already exists");
        }
        if (entityAddress == address(0)) {
            revert("Entity address cannot be zero");
        }
        if (bytes(entityType).length == 0 || bytes(entityType).length > 50) {
            revert("Invalid entity type length");
        }
        if (bytes(metadataURI).length > 200) {
            revert("Metadata URI too long");
        }

        // Rate limiting
        SubmissionInfo storage entityInfo = submissionInfo[msg.sender];
        if (block.timestamp >= entityInfo.lastSubmissionTimestamp + SUBMISSION_WINDOW) {
            entityInfo.submissionCount = 0;
            entityInfo.lastSubmissionTimestamp = block.timestamp;
        } else {
            if (block.timestamp < entityInfo.lastSubmissionTimestamp + MIN_SUBMISSION_INTERVAL) {
                revert("Submission interval too short");
            }
            if (entityInfo.submissionCount >= MAX_SUBMISSIONS_PER_WINDOW) {
                emit RateLimitTriggered(msg.sender, block.timestamp);
                revert("Submission limit exceeded");
            }
        }

        entityInfo.submissionCount += 1;

        entities[entityId] = Entity({
            entityId: entityId,
            entityAddress: entityAddress,
            entityType: entityType,
            dataHash: dataHash,
            metadataURI: metadataURI,
            registrationTimestamp: block.timestamp,
            status: EntityStatus.Pending,
            registrar: msg.sender
        });

        emit EntitySubmitted(entityId, entityAddress, entityType, dataHash, metadataURI, block.timestamp, msg.sender);
    }

    // Function to register an entity
    function registerEntity(bytes32 entityId, string calldata reason) external onlyAuthorizedRegistrar entityPending(entityId) {
        entities[entityId].status = EntityStatus.Registered;
        entities[entityId].registrar = msg.sender;
        entities[entityId].registrationTimestamp = block.timestamp;

        emit EntityProcessed(entityId, EntityStatus.Registered, msg.sender, block.timestamp, reason);
    }

    // Function to deregister an entity
    function deregisterEntity(bytes32 entityId, string calldata reason) external onlyAuthorizedRegistrar {
        if (entities[entityId].status != EntityStatus.Registered) {
            revert("Entity must be registered to deregister");
        }
        entities[entityId].status = EntityStatus.Deregistered;
        entities[entityId].registrar = msg.sender;
        entities[entityId].registrationTimestamp = block.timestamp;

        emit EntityProcessed(entityId, EntityStatus.Deregistered, msg.sender, block.timestamp, reason);
    }

    // Function to submit a derived relationship with rate limiting
    function submitRelationship(
        bytes32 relationshipId,
        bytes32 parentEntityId,
        bytes32 childEntityId,
        string calldata relationshipType,
        bytes32 dataHash,
        string calldata metadataURI
    ) external onlyAuthorizedRegistrar {
        if (relationships[relationshipId].status != RelationshipStatus.Pending) {
            revert("Relationship ID already exists");
        }
        if (entities[parentEntityId].status != EntityStatus.Registered) {
            revert("Parent entity must be registered");
        }
        if (entities[childEntityId].status != EntityStatus.Registered) {
            revert("Child entity must be registered");
        }
        if (bytes(relationshipType).length == 0 || bytes(relationshipType).length > 50) {
            revert("Invalid relationship type length");
        }
        if (bytes(metadataURI).length > 200) {
            revert("Metadata URI too long");
        }

        // Rate limiting
        SubmissionInfo storage entityInfo = submissionInfo[msg.sender];
        if (block.timestamp >= entityInfo.lastSubmissionTimestamp + SUBMISSION_WINDOW) {
            entityInfo.submissionCount = 0;
            entityInfo.lastSubmissionTimestamp = block.timestamp;
        } else {
            if (block.timestamp < entityInfo.lastSubmissionTimestamp + MIN_SUBMISSION_INTERVAL) {
                revert("Submission interval too short");
            }
            if (entityInfo.submissionCount >= MAX_SUBMISSIONS_PER_WINDOW) {
                emit RateLimitTriggered(msg.sender, block.timestamp);
                revert("Submission limit exceeded");
            }
        }

        entityInfo.submissionCount += 1;

        relationships[relationshipId] = Relationship({
            relationshipId: relationshipId,
            parentEntityId: parentEntityId,
            childEntityId: childEntityId,
            relationshipType: relationshipType,
            dataHash: dataHash,
            metadataURI: metadataURI,
            creationTimestamp: block.timestamp,
            terminationTimestamp: 0,
            status: RelationshipStatus.Pending,
            creator: msg.sender
        });

        emit RelationshipSubmitted(
            relationshipId,
            parentEntityId,
            childEntityId,
            relationshipType,
            dataHash,
            metadataURI,
            block.timestamp,
            msg.sender
        );
    }

    // Function to activate a relationship
    function activateRelationship(bytes32 relationshipId, string calldata reason) external onlyAuthorizedRegistrar relationshipPending(relationshipId) {
        relationships[relationshipId].status = RelationshipStatus.Active;
        relationships[relationshipId].creator = msg.sender;
        relationships[relationshipId].creationTimestamp = block.timestamp;

        emit RelationshipProcessed(relationshipId, RelationshipStatus.Active, msg.sender, block.timestamp, reason);
    }

    // Function to terminate a relationship
    function terminateRelationship(bytes32 relationshipId, string calldata reason) external onlyAuthorizedRegistrar {
        if (relationships[relationshipId].status != RelationshipStatus.Active) {
            revert("Relationship must be active to terminate");
        }
        relationships[relationshipId].status = RelationshipStatus.Terminated;
        relationships[relationshipId].creator = msg.sender;
        relationships[relationshipId].terminationTimestamp = block.timestamp;

        emit RelationshipProcessed(relationshipId, RelationshipStatus.Terminated, msg.sender, block.timestamp, reason);
    }

    // Function to submit a data access permission request
    function submitPermission(
        bytes32 permissionId,
        bytes32 entityId,
        bytes32 dataId,
        string calldata metadataURI
    ) external onlyAuthorizedRegistrar {
        if (permissions[permissionId].status != PermissionStatus.Pending) {
            revert("Permission ID already exists");
        }
        if (entities[entityId].status != EntityStatus.Registered) {
            revert("Entity must be registered");
        }
        if (bytes(metadataURI).length > 200) {
            revert("Metadata URI too long");
        }

        // Rate limiting
        SubmissionInfo storage entityInfo = submissionInfo[msg.sender];
        if (block.timestamp >= entityInfo.lastSubmissionTimestamp + SUBMISSION_WINDOW) {
            entityInfo.submissionCount = 0;
            entityInfo.lastSubmissionTimestamp = block.timestamp;
        } else {
            if (block.timestamp < entityInfo.lastSubmissionTimestamp + MIN_SUBMISSION_INTERVAL) {
                revert("Submission interval too short");
            }
            if (entityInfo.submissionCount >= MAX_SUBMISSIONS_PER_WINDOW) {
                emit RateLimitTriggered(msg.sender, block.timestamp);
                revert("Submission limit exceeded");
            }
        }

        entityInfo.submissionCount += 1;

        permissions[permissionId] = DataAccessPermission({
            permissionId: permissionId,
            entityId: entityId,
            dataId: dataId,
            metadataURI: metadataURI,
            timestamp: block.timestamp,
            revocationTimestamp: 0,
            status: PermissionStatus.Pending,
            reviewer: msg.sender
        });

        emit PermissionSubmitted(permissionId, entityId, dataId, metadataURI, block.timestamp, msg.sender);
    }

    // Function to grant a data access permission
    function grantPermission(bytes32 permissionId, string calldata reason) external onlyAuthorizedRegistrar permissionPending(permissionId) {
        permissions[permissionId].status = PermissionStatus.Granted;
        permissions[permissionId].reviewer = msg.sender;
        permissions[permissionId].timestamp = block.timestamp;

        emit PermissionProcessed(permissionId, PermissionStatus.Granted, msg.sender, block.timestamp, reason);
    }

    // Function to revoke a data access permission
    function revokePermission(bytes32 permissionId, string calldata reason) external onlyAuthorizedRegistrar {
        if (permissions[permissionId].status != PermissionStatus.Granted) {
            revert("Permission must be granted to revoke");
        }
        permissions[permissionId].status = PermissionStatus.Revoked;
        permissions[permissionId].reviewer = msg.sender;
        permissions[permissionId].revocationTimestamp = block.timestamp;

        emit PermissionProcessed(permissionId, PermissionStatus.Revoked, msg.sender, block.timestamp, reason);
    }

    // Function to verify an entity's data hash
    function verifyEntityHash(bytes32 entityId, bytes32 dataHash) external view returns (bool) {
        return entities[entityId].dataHash == dataHash && entities[entityId].status == EntityStatus.Registered;
    }

    // Function to verify a relationship's data hash
    function verifyRelationshipHash(bytes32 relationshipId, bytes32 dataHash) external view returns (bool) {
        return relationships[relationshipId].dataHash == dataHash && relationships[relationshipId].status == RelationshipStatus.Active;
    }

    // Function to verify a permission's data ID hash
    function verifyPermissionHash(bytes32 permissionId, bytes32 dataId) external view returns (bool) {
        return permissions[permissionId].dataId == dataId && permissions[permissionId].status == PermissionStatus.Granted;
    }

    // Function to get entity details
    function getEntityDetails(bytes32 entityId)
        external
        view
        returns (
            address entityAddress,
            string memory entityType,
            bytes32 dataHash,
            string memory metadataURI,
            uint256 registrationTimestamp,
            EntityStatus status,
            address registrar
        )
    {
        if (
            msg.sender != owner &&
            msg.sender != entities[entityId].entityAddress &&
            msg.sender != entities[entityId].registrar &&
            !authorizedRegistrars[msg.sender]
        ) {
            revert("Not authorized to view entity details");
        }

        Entity memory entity = entities[entityId];
        return (
            entity.entityAddress,
            entity.entityType,
            entity.dataHash,
            entity.metadataURI,
            entity.registrationTimestamp,
            entity.status,
            entity.registrar
        );
    }

    // Function to get relationship details
    function getRelationshipDetails(bytes32 relationshipId)
        external
        view
        returns (
            bytes32 parentEntityId,
            bytes32 childEntityId,
            string memory relationshipType,
            bytes32 dataHash,
            string memory metadataURI,
            uint256 creationTimestamp,
            uint256 terminationTimestamp,
            RelationshipStatus status,
            address creator
        )
    {
        if (
            msg.sender != owner &&
            msg.sender != relationships[relationshipId].creator &&
            !authorizedRegistrars[msg.sender]
        ) {
            revert("Not authorized to view relationship details");
        }

        Relationship memory relationship = relationships[relationshipId];
        return (
            relationship.parentEntityId,
            relationship.childEntityId,
            relationship.relationshipType,
            relationship.dataHash,
            relationship.metadataURI,
            relationship.creationTimestamp,
            relationship.terminationTimestamp,
            relationship.status,
            relationship.creator
        );
    }

    // Function to get data access permission details
    function getPermissionDetails(bytes32 permissionId)
        external
        view
        returns (
            bytes32 entityId,
            bytes32 dataId,
            string memory metadataURI,
            uint256 timestamp,
            uint256 revocationTimestamp,
            PermissionStatus status,
            address reviewer
        )
    {
        if (
            msg.sender != owner &&
            msg.sender != entities[permissions[permissionId].entityId].entityAddress &&
            msg.sender != permissions[permissionId].reviewer &&
            !authorizedRegistrars[msg.sender]
        ) {
            revert("Not authorized to view permission details");
        }

        DataAccessPermission memory permission = permissions[permissionId];
        return (
            permission.entityId,
            permission.dataId,
            permission.metadataURI,
            permission.timestamp,
            permission.revocationTimestamp,
            permission.status,
            permission.reviewer
        );
    }

    // Function to authorize or deauthorize a registrar
    function setRegistrarAuthorization(address registrar, bool authorized) external onlyOwner {
        if (registrar == address(0)) {
            revert("Registrar address cannot be zero");
        }
        if (authorizedRegistrars[registrar] == authorized) {
            revert("Authorization status already set");
        }

        authorizedRegistrars[registrar] = authorized;
        emit RegistrarAuthorizationUpdated(registrar, authorized, block.timestamp);
    }

    // Function to transfer ownership (simulated via authorization)
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) {
            revert("New owner cannot be zero address");
        }
        authorizedRegistrars[owner] = false; // Remove old owner as authorized registrar
        authorizedRegistrars[newOwner] = true; // New owner becomes authorized
        emit RegistrarAuthorizationUpdated(newOwner, true, block.timestamp);
    }
}