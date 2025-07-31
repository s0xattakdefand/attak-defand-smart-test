// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// DerivedPIVManager contract for managing Derived Personal Identity Verification credentials
contract DerivedPIVManager {
    // Contract owner (e.g., Agency Identity Management Office)
    address public owner;

    // Structure to store Derived PIV credential
    struct DerivedPIVCredential {
        bytes32 credentialId; // Unique identifier for the Derived PIV credential
        address holder; // Address of the credential holder (e.g., employee, contractor)
        bytes32 primaryPIVHash; // Hash of primary PIV credential (e.g., CAC/PIV card)
        string credentialType; // Type of derived credential (e.g., Mobile Certificate, Soft Token)
        bytes32 dataHash; // Hash of credential details (using keccak256)
        string metadataURI; // Off-chain URI for detailed metadata (e.g., IPFS link)
        uint256 issuanceTimestamp; // Timestamp of credential issuance
        uint256 expirationTimestamp; // Timestamp of credential expiration
        uint256 revocationTimestamp; // Timestamp of credential revocation (0 if active)
        CredentialStatus status; // Status of the credential
        address issuer; // Address of the entity issuing/revoking the credential
    }

    // Structure to store data access permission
    struct DataAccessPermission {
        bytes32 permissionId; // Unique identifier for the permission
        address holder; // Address of the credential holder with access
        bytes32 dataId; // Hashed identifier for sensitive data (e.g., CUI)
        string metadataURI; // Off-chain URI for permission details
        uint256 timestamp; // Timestamp of permission grant
        uint256 revocationTimestamp; // Timestamp of permission revocation (0 if active)
        PermissionStatus status; // Status of the permission
        address reviewer; // Address of the entity granting/revoking permission
    }

    // Enum for credential status
    enum CredentialStatus { Pending, Issued, Revoked, Expired }

    // Enum for data access permission status
    enum PermissionStatus { Pending, Granted, Revoked }

    // Structure to store submission metadata for rate limiting
    struct SubmissionInfo {
        uint256 lastSubmissionTimestamp; // Timestamp of last submission
        uint256 submissionCount; // Number of submissions in current window
    }

    // Mapping to store Derived PIV credentials by credential ID
    mapping(bytes32 => DerivedPIVCredential) public credentials;

    // Mapping to store data access permissions by permission ID
    mapping(bytes32 => DataAccessPermission) public permissions;

    // Mapping to store authorized issuers (e.g., agency officials)
    mapping(address => bool) public authorizedIssuers;

    // Mapping to store submission metadata for rate limiting
    mapping(address => SubmissionInfo) public submissionInfo;

    // Rate limit parameters to prevent DoS
    uint256 public constant SUBMISSION_WINDOW = 1 hours; // Time window for rate limiting
    uint256 public constant MAX_SUBMISSIONS_PER_WINDOW = 5; // Max submissions per window
    uint256 public constant MIN_SUBMISSION_INTERVAL = 10 seconds; // Minimum time between submissions

    // Default credential validity period (e.g., 3 years, per NIST 800-157)
    uint256 public constant DEFAULT_VALIDITY_PERIOD = 3 * 365 days;

    // Event emitted when a Derived PIV credential is submitted
    event CredentialSubmitted(
        bytes32 indexed credentialId,
        address indexed holder,
        bytes32 primaryPIVHash,
        string credentialType,
        bytes32 dataHash,
        string metadataURI,
        uint256 issuanceTimestamp,
        uint256 expirationTimestamp
    );

    // Event emitted when a Derived PIV credential is processed (issued, revoked, or expired)
    event CredentialProcessed(
        bytes32 indexed credentialId,
        CredentialStatus status,
        address indexed issuer,
        uint256 timestamp
    );

    // Event emitted when a data access permission is submitted
    event PermissionSubmitted(
        bytes32 indexed permissionId,
        address indexed holder,
        bytes32 dataId,
        string metadataURI,
        uint256 timestamp
    );

    // Event emitted when a data access permission is processed (granted or revoked)
    event PermissionProcessed(
        bytes32 indexed permissionId,
        PermissionStatus status,
        address indexed reviewer,
        uint256 timestamp
    );

    // Event emitted when an issuer is authorized or deauthorized
    event IssuerAuthorizationUpdated(address indexed issuer, bool authorized, uint256 timestamp);

    // Event emitted when rate limit is triggered
    event RateLimitTriggered(address indexed entity, uint256 timestamp);

    // Modifier to restrict functions to the contract owner
    modifier onlyOwner() {
        if (msg.sender != owner) {
            revert("Only owner can call this function");
        }
        _;
    }

    // Modifier to restrict functions to authorized issuers
    modifier onlyAuthorizedIssuer() {
        if (!authorizedIssuers[msg.sender]) {
            revert("Only authorized issuers can call this function");
        }
        _;
    }

    // Modifier to check if a credential is pending
    modifier credentialPending(bytes32 credentialId) {
        if (credentials[credentialId].status != CredentialStatus.Pending) {
            revert("Credential not pending or does not exist");
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

    // Constructor to set the owner
    constructor() {
        owner = msg.sender;
        authorizedIssuers[msg.sender] = true; // Owner is authorized by default
    }

    // Function to submit a Derived PIV credential for issuance with rate limiting
    function submitCredential(
        bytes32 credentialId,
        address holder,
        bytes32 primaryPIVHash,
        string calldata credentialType,
        bytes32 dataHash,
        string calldata metadataURI,
        uint256 validityPeriod
    ) external onlyAuthorizedIssuer {
        if (credentials[credentialId].status != CredentialStatus.Pending) {
            revert("Credential ID already exists");
        }
        if (holder == address(0)) {
            revert("Holder address cannot be zero");
        }
        if (primaryPIVHash == bytes32(0)) {
            revert("Primary PIV hash cannot be zero");
        }
        if (bytes(credentialType).length == 0 || bytes(credentialType).length > 50) {
            revert("Invalid credential type length");
        }
        if (bytes(metadataURI).length > 200) {
            revert("Metadata URI too long");
        }
        if (validityPeriod == 0 || validityPeriod > DEFAULT_VALIDITY_PERIOD) {
            revert("Invalid validity period");
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

        credentials[credentialId] = DerivedPIVCredential({
            credentialId: credentialId,
            holder: holder,
            primaryPIVHash: primaryPIVHash,
            credentialType: credentialType,
            dataHash: dataHash,
            metadataURI: metadataURI,
            issuanceTimestamp: block.timestamp,
            expirationTimestamp: block.timestamp + validityPeriod,
            revocationTimestamp: 0,
            status: CredentialStatus.Pending,
            issuer: msg.sender
        });

        emit CredentialSubmitted(
            credentialId,
            holder,
            primaryPIVHash,
            credentialType,
            dataHash,
            metadataURI,
            block.timestamp,
            block.timestamp + validityPeriod
        );
    }

    // Function to issue a Derived PIV credential
    function issueCredential(bytes32 credentialId) external onlyAuthorizedIssuer credentialPending(credentialId) {
        if (block.timestamp >= credentials[credentialId].expirationTimestamp) {
            credentials[credentialId].status = CredentialStatus.Expired;
            emit CredentialProcessed(credentialId, CredentialStatus.Expired, msg.sender, block.timestamp);
            revert("Credential has expired");
        }

        credentials[credentialId].status = CredentialStatus.Issued;
        credentials[credentialId].issuer = msg.sender;
        credentials[credentialId].issuanceTimestamp = block.timestamp;

        emit CredentialProcessed(credentialId, CredentialStatus.Issued, msg.sender, block.timestamp);
    }

    // Function to revoke a Derived PIV credential
    function revokeCredential(bytes32 credentialId) external onlyAuthorizedIssuer {
        if (credentials[credentialId].status != CredentialStatus.Issued) {
            revert("Credential must be issued to revoke");
        }
        credentials[credentialId].status = CredentialStatus.Revoked;
        credentials[credentialId].issuer = msg.sender;
        credentials[credentialId].revocationTimestamp = block.timestamp;

        emit CredentialProcessed(credentialId, CredentialStatus.Revoked, msg.sender, block.timestamp);
    }

    // Function to check and mark expired credentials
    function markExpiredCredential(bytes32 credentialId) external onlyAuthorizedIssuer {
        if (credentials[credentialId].status != CredentialStatus.Issued) {
            revert("Credential must be issued to mark as expired");
        }
        if (block.timestamp < credentials[credentialId].expirationTimestamp) {
            revert("Credential has not yet expired");
        }
        credentials[credentialId].status = CredentialStatus.Expired;
        credentials[credentialId].issuer = msg.sender;
        credentials[credentialId].revocationTimestamp = block.timestamp;

        emit CredentialProcessed(credentialId, CredentialStatus.Expired, msg.sender, block.timestamp);
    }

    // Function to submit a data access permission request
    function submitPermission(
        bytes32 permissionId,
        address holder,
        bytes32 dataId,
        string calldata metadataURI
    ) external onlyAuthorizedIssuer {
        if (permissions[permissionId].status != PermissionStatus.Pending) {
            revert("Permission ID already exists");
        }
        if (holder == address(0)) {
            revert("Holder address cannot be zero");
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
            holder: holder,
            dataId: dataId,
            metadataURI: metadataURI,
            timestamp: block.timestamp,
            revocationTimestamp: 0,
            status: PermissionStatus.Pending,
            reviewer: address(0)
        });

        emit PermissionSubmitted(permissionId, holder, dataId, metadataURI, block.timestamp);
    }

    // Function to grant a data access permission
    function grantPermission(bytes32 permissionId) external onlyAuthorizedIssuer permissionPending(permissionId) {
        permissions[permissionId].status = PermissionStatus.Granted;
        permissions[permissionId].reviewer = msg.sender;
        permissions[permissionId].timestamp = block.timestamp;

        emit PermissionProcessed(permissionId, PermissionStatus.Granted, msg.sender, block.timestamp);
    }

    // Function to revoke a data access permission
    function revokePermission(bytes32 permissionId) external onlyAuthorizedIssuer {
        if (permissions[permissionId].status != PermissionStatus.Granted) {
            revert("Permission must be granted to revoke");
        }
        permissions[permissionId].status = PermissionStatus.Revoked;
        permissions[permissionId].reviewer = msg.sender;
        permissions[permissionId].revocationTimestamp = block.timestamp;

        emit PermissionProcessed(permissionId, PermissionStatus.Revoked, msg.sender, block.timestamp);
    }

    // Function to verify a credential's data hash
    function verifyCredentialHash(bytes32 credentialId, bytes32 dataHash) external view returns (bool) {
        return credentials[credentialId].dataHash == dataHash &&
               credentials[credentialId].status != CredentialStatus.Revoked &&
               credentials[credentialId].status != CredentialStatus.Expired &&
               block.timestamp < credentials[credentialId].expirationTimestamp;
    }

    // Function to verify a permission's data ID hash
    function verifyPermissionHash(bytes32 permissionId, bytes32 dataId) external view returns (bool) {
        return permissions[permissionId].dataId == dataId && permissions[permissionId].status != PermissionStatus.Revoked;
    }

    // Function to get Derived PIV credential details
    function getCredentialDetails(bytes32 credentialId)
        external
        view
        returns (
            address holder,
            bytes32 primaryPIVHash,
            string memory credentialType,
            bytes32 dataHash,
            string memory metadataURI,
            uint256 issuanceTimestamp,
            uint256 expirationTimestamp,
            uint256 revocationTimestamp,
            CredentialStatus status,
            address issuer
        )
    {
        if (
            msg.sender != owner &&
            msg.sender != credentials[credentialId].holder &&
            msg.sender != credentials[credentialId].issuer &&
            !authorizedIssuers[msg.sender]
        ) {
            revert("Not authorized to view credential details");
        }

        DerivedPIVCredential memory credential = credentials[credentialId];
        return (
            credential.holder,
            credential.primaryPIVHash,
            credential.credentialType,
            credential.dataHash,
            credential.metadataURI,
            credential.issuanceTimestamp,
            credential.expirationTimestamp,
            credential.revocationTimestamp,
            credential.status,
            credential.issuer
        );
    }

    // Function to get data access permission details
    function getPermissionDetails(bytes32 permissionId)
        external
        view
        returns (
            address holder,
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
            msg.sender != permissions[permissionId].holder &&
            msg.sender != permissions[permissionId].reviewer &&
            !authorizedIssuers[msg.sender]
        ) {
            revert("Not authorized to view permission details");
        }

        DataAccessPermission memory permission = permissions[permissionId];
        return (
            permission.holder,
            permission.dataId,
            permission.metadataURI,
            permission.timestamp,
            permission.revocationTimestamp,
            permission.status,
            permission.reviewer
        );
    }

    // Function to authorize or deauthorize an issuer
    function setIssuerAuthorization(address issuer, bool authorized) external onlyOwner {
        if (issuer == address(0)) {
            revert("Issuer address cannot be zero");
        }
        if (authorizedIssuers[issuer] == authorized) {
            revert("Authorization status already set");
        }

        authorizedIssuers[issuer] = authorized;
        emit IssuerAuthorizationUpdated(issuer, authorized, block.timestamp);
    }

    // Function to transfer ownership
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) {
            revert("New owner cannot be zero address");
        }
        authorizedIssuers[owner] = false; // Remove old owner as authorized issuer
        owner = newOwner;
        authorizedIssuers[newOwner] = true; // New owner becomes authorized
        emit IssuerAuthorizationUpdated(newOwner, true, block.timestamp);
    }
}