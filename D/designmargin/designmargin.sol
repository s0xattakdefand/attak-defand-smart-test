// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// DesignMarginManager contract for managing design margins and access permissions
contract DesignMarginManager {
    // Contract owner (e.g., Agency Engineering Office)
    address public immutable owner;

    // Structure to store a design artifact
    struct DesignArtifact {
        bytes32 designId; // Unique identifier for the design artifact
        address creator; // Address of the entity creating the design
        string designType; // Type of design (e.g., Blueprint, System Component)
        bytes32 dataHash; // Hash of design details (using keccak256)
        string metadataURI; // Off-chain URI for design metadata (e.g., IPFS link)
        uint256 creationTimestamp; // Timestamp of design creation
        DesignStatus status; // Status of the design artifact
        address approver; // Address of the entity approving/rejecting the design
    }

    // Structure to store a design margin
    struct DesignMargin {
        bytes32 marginId; // Unique identifier for the margin
        bytes32 designId; // ID of the associated design artifact
        string marginType; // Type of margin (e.g., Safety Factor, Thermal Tolerance)
        bytes32 valueHash; // Hash of margin value (using keccak256)
        string metadataURI; // Off-chain URI for margin details (e.g., IPFS link)
        uint256 submissionTimestamp; // Timestamp of margin submission
        MarginStatus status; // Status of the margin
        address submitter; // Address of the entity submitting/updating the margin
    }

    // Structure to store data access permission for a margin
    struct DataAccessPermission {
        bytes32 permissionId; // Unique identifier for the permission
        bytes32 marginId; // ID of the design margin
        address accessor; // Address of the entity granted access
        string metadataURI; // Off-chain URI for permission details
        uint256 timestamp; // Timestamp of permission grant
        uint256 revocationTimestamp; // Timestamp of permission revocation (0 if active)
        PermissionStatus status; // Status of the permission
        address reviewer; // Address of the entity granting/revoking permission
    }

    // Enum for design artifact status
    enum DesignStatus { Pending, Approved, Rejected }

    // Enum for design margin status
    enum MarginStatus { Pending, Approved, Rejected }

    // Enum for data access permission status
    enum PermissionStatus { Pending, Granted, Revoked }

    // Structure to store submission metadata for rate limiting
    struct SubmissionInfo {
        uint256 lastSubmissionTimestamp; // Timestamp of last submission
        uint256 submissionCount; // Number of submissions in current window
    }

    // Mapping to store design artifacts by design ID
    mapping(bytes32 => DesignArtifact) public designs;

    // Mapping to store design margins by margin ID
    mapping(bytes32 => DesignMargin) public margins;

    // Mapping to store data access permissions by permission ID
    mapping(bytes32 => DataAccessPermission) public permissions;

    // Mapping to store authorized approvers (e.g., agency officials)
    mapping(address => bool) public authorizedApprovers;

    // Mapping to store submission metadata for rate limiting
    mapping(address => SubmissionInfo) public submissionInfo;

    // Rate limit parameters to prevent DoS
    uint256 public constant SUBMISSION_WINDOW = 1 hours; // Time window for rate limiting
    uint256 public constant MAX_SUBMISSIONS_PER_WINDOW = 5; // Max submissions per window
    uint256 public constant MIN_SUBMISSION_INTERVAL = 10 seconds; // Minimum time between submissions

    // Event emitted when a design artifact is submitted
    event DesignSubmitted(
        bytes32 indexed designId,
        address indexed creator,
        string designType,
        bytes32 dataHash,
        string metadataURI,
        uint256 timestamp
    );

    // Event emitted when a design artifact is processed (approved or rejected)
    event DesignProcessed(
        bytes32 indexed designId,
        DesignStatus status,
        address indexed approver,
        uint256 timestamp,
        string reason
    );

    // Event emitted when a design margin is submitted
    event MarginSubmitted(
        bytes32 indexed marginId,
        bytes32 indexed designId,
        string marginType,
        bytes32 valueHash,
        string metadataURI,
        uint256 timestamp,
        address indexed submitter
    );

    // Event emitted when a design margin is processed (approved or rejected)
    event MarginProcessed(
        bytes32 indexed marginId,
        MarginStatus status,
        address indexed submitter,
        uint256 timestamp,
        string reason
    );

    // Event emitted when a data access permission is submitted
    event PermissionSubmitted(
        bytes32 indexed permissionId,
        bytes32 indexed marginId,
        address indexed accessor,
        string metadataURI,
        uint256 timestamp
    );

    // Event emitted when a data access permission is processed (granted or revoked)
    event PermissionProcessed(
        bytes32 indexed permissionId,
        PermissionStatus status,
        address indexed reviewer,
        uint256 timestamp,
        string reason
    );

    // Event emitted when an approver is authorized or deauthorized
    event ApproverAuthorizationUpdated(address indexed approver, bool authorized, uint256 timestamp);

    // Event emitted when rate limit is triggered
    event RateLimitTriggered(address indexed entity, uint256 timestamp);

    // Modifier to restrict functions to the contract owner
    modifier onlyOwner() {
        if (msg.sender != owner) {
            revert("Only owner can call this function");
        }
        _;
    }

    // Modifier to restrict functions to authorized approvers
    modifier onlyAuthorizedApprover() {
        if (!authorizedApprovers[msg.sender]) {
            revert("Only authorized approvers can call this function");
        }
        _;
    }

    // Modifier to check if a design is pending
    modifier designPending(bytes32 designId) {
        if (designs[designId].status != DesignStatus.Pending) {
            revert("Design not pending or does not exist");
        }
        _;
    }

    // Modifier to check if a margin is pending
    modifier marginPending(bytes32 marginId) {
        if (margins[marginId].status != MarginStatus.Pending) {
            revert("Margin not pending or does not exist");
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
        authorizedApprovers[msg.sender] = true; // Owner is authorized by default
    }

    // Function to submit a design artifact with rate limiting
    function submitDesign(
        bytes32 designId,
        string calldata designType,
        bytes32 dataHash,
        string calldata metadataURI
    ) external {
        if (designs[designId].status != DesignStatus.Pending) {
            revert("Design ID already exists");
        }
        if (bytes(designType).length == 0 || bytes(designType).length > 50) {
            revert("Invalid design type length");
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

        designs[designId] = DesignArtifact({
            designId: designId,
            creator: msg.sender,
            designType: designType,
            dataHash: dataHash,
            metadataURI: metadataURI,
            creationTimestamp: block.timestamp,
            status: DesignStatus.Pending,
            approver: address(0)
        });

        emit DesignSubmitted(designId, msg.sender, designType, dataHash, metadataURI, block.timestamp);
    }

    // Function to approve a design artifact
    function approveDesign(bytes32 designId, string calldata reason) external onlyAuthorizedApprover designPending(designId) {
        designs[designId].status = DesignStatus.Approved;
        designs[designId].approver = msg.sender;
        designs[designId].creationTimestamp = block.timestamp;

        emit DesignProcessed(designId, DesignStatus.Approved, msg.sender, block.timestamp, reason);
    }

    // Function to reject a design artifact
    function rejectDesign(bytes32 designId, string calldata reason) external onlyAuthorizedApprover designPending(designId) {
        designs[designId].status = DesignStatus.Rejected;
        designs[designId].approver = msg.sender;
        designs[designId].creationTimestamp = block.timestamp;

        emit DesignProcessed(designId, DesignStatus.Rejected, msg.sender, block.timestamp, reason);
    }

    // Function to submit a design margin with rate limiting
    function submitMargin(
        bytes32 marginId,
        bytes32 designId,
        string calldata marginType,
        bytes32 valueHash,
        string calldata metadataURI
    ) external {
        if (margins[marginId].status != MarginStatus.Pending) {
            revert("Margin ID already exists");
        }
        if (designs[designId].status != DesignStatus.Approved) {
            revert("Design must be approved");
        }
        if (bytes(marginType).length == 0 || bytes(marginType).length > 50) {
            revert("Invalid margin type length");
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

        margins[marginId] = DesignMargin({
            marginId: marginId,
            designId: designId,
            marginType: marginType,
            valueHash: valueHash,
            metadataURI: metadataURI,
            submissionTimestamp: block.timestamp,
            status: MarginStatus.Pending,
            submitter: msg.sender
        });

        emit MarginSubmitted(marginId, designId, marginType, valueHash, metadataURI, block.timestamp, msg.sender);
    }

    // Function to approve a design margin
    function approveMargin(bytes32 marginId, string calldata reason) external onlyAuthorizedApprover marginPending(marginId) {
        margins[marginId].status = MarginStatus.Approved;
        margins[marginId].submitter = msg.sender;
        margins[marginId].submissionTimestamp = block.timestamp;

        emit MarginProcessed(marginId, MarginStatus.Approved, msg.sender, block.timestamp, reason);
    }

    // Function to reject a design margin
    function rejectMargin(bytes32 marginId, string calldata reason) external onlyAuthorizedApprover marginPending(marginId) {
        margins[marginId].status = MarginStatus.Rejected;
        margins[marginId].submitter = msg.sender;
        margins[marginId].submissionTimestamp = block.timestamp;

        emit MarginProcessed(marginId, MarginStatus.Rejected, msg.sender, block.timestamp, reason);
    }

    // Function to submit a data access permission request
    function submitPermission(
        bytes32 permissionId,
        bytes32 marginId,
        address accessor,
        string calldata metadataURI
    ) external onlyAuthorizedApprover {
        if (permissions[permissionId].status != PermissionStatus.Pending) {
            revert("Permission ID already exists");
        }
        if (margins[marginId].status != MarginStatus.Approved) {
            revert("Margin must be approved");
        }
        if (accessor == address(0)) {
            revert("Accessor address cannot be zero");
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
            marginId: marginId,
            accessor: accessor,
            metadataURI: metadataURI,
            timestamp: block.timestamp,
            revocationTimestamp: 0,
            status: PermissionStatus.Pending,
            reviewer: msg.sender
        });

        emit PermissionSubmitted(permissionId, marginId, accessor, metadataURI, block.timestamp);
    }

    // Function to grant a data access permission
    function grantPermission(bytes32 permissionId, string calldata reason) external onlyAuthorizedApprover permissionPending(permissionId) {
        permissions[permissionId].status = PermissionStatus.Granted;
        permissions[permissionId].reviewer = msg.sender;
        permissions[permissionId].timestamp = block.timestamp;

        emit PermissionProcessed(permissionId, PermissionStatus.Granted, msg.sender, block.timestamp, reason);
    }

    // Function to revoke a data access permission
    function revokePermission(bytes32 permissionId, string calldata reason) external onlyAuthorizedApprover {
        if (permissions[permissionId].status != PermissionStatus.Granted) {
            revert("Permission must be granted to revoke");
        }
        permissions[permissionId].status = PermissionStatus.Revoked;
        permissions[permissionId].reviewer = msg.sender;
        permissions[permissionId].revocationTimestamp = block.timestamp;

        emit PermissionProcessed(permissionId, PermissionStatus.Revoked, msg.sender, block.timestamp, reason);
    }

    // Function to verify a design's data hash
    function verifyDesignHash(bytes32 designId, bytes32 dataHash) external view returns (bool) {
        return designs[designId].dataHash == dataHash && designs[designId].status == DesignStatus.Approved;
    }

    // Function to verify a margin's value hash
    function verifyMarginHash(bytes32 marginId, bytes32 valueHash) external view returns (bool) {
        return margins[marginId].valueHash == valueHash && margins[marginId].status == MarginStatus.Approved;
    }

    // Function to verify a permission's margin ID
    function verifyPermissionHash(bytes32 permissionId, bytes32 marginId) external view returns (bool) {
        return permissions[permissionId].marginId == marginId && permissions[permissionId].status == PermissionStatus.Granted;
    }

    // Function to get design artifact details
    function getDesignDetails(bytes32 designId)
        external
        view
        returns (
            address creator,
            string memory designType,
            bytes32 dataHash,
            string memory metadataURI,
            uint256 creationTimestamp,
            DesignStatus status,
            address approver
        )
    {
        if (
            msg.sender != owner &&
            msg.sender != designs[designId].creator &&
            msg.sender != designs[designId].approver &&
            !authorizedApprovers[msg.sender]
        ) {
            revert("Not authorized to view design details");
        }

        DesignArtifact memory design = designs[designId];
        return (
            design.creator,
            design.designType,
            design.dataHash,
            design.metadataURI,
            design.creationTimestamp,
            design.status,
            design.approver
        );
    }

    // Function to get design margin details
    function getMarginDetails(bytes32 marginId)
        external
        view
        returns (
            bytes32 designId,
            string memory marginType,
            bytes32 valueHash,
            string memory metadataURI,
            uint256 submissionTimestamp,
            MarginStatus status,
            address submitter
        )
    {
        if (
            msg.sender != owner &&
            msg.sender != margins[marginId].submitter &&
            !authorizedApprovers[msg.sender]
        ) {
            revert("Not authorized to view margin details");
        }

        DesignMargin memory margin = margins[marginId];
        return (
            margin.designId,
            margin.marginType,
            margin.valueHash,
            margin.metadataURI,
            margin.submissionTimestamp,
            margin.status,
            margin.submitter
        );
    }

    // Function to get data access permission details
    function getPermissionDetails(bytes32 permissionId)
        external
        view
        returns (
            bytes32 marginId,
            address accessor,
            string memory metadataURI,
            uint256 timestamp,
            uint256 revocationTimestamp,
            PermissionStatus status,
            address reviewer
        )
    {
        if (
            msg.sender != owner &&
            msg.sender != permissions[permissionId].accessor &&
            msg.sender != permissions[permissionId].reviewer &&
            !authorizedApprovers[msg.sender]
        ) {
            revert("Not authorized to view permission details");
        }

        DataAccessPermission memory permission = permissions[permissionId];
        return (
            permission.marginId,
            permission.accessor,
            permission.metadataURI,
            permission.timestamp,
            permission.revocationTimestamp,
            permission.status,
            permission.reviewer
        );
    }

    // Function to authorize or deauthorize an approver
    function setApproverAuthorization(address approver, bool authorized) external onlyOwner {
        if (approver == address(0)) {
            revert("Approver address cannot be zero");
        }
        if (authorizedApprovers[approver] == authorized) {
            revert("Authorization status already set");
        }

        authorizedApprovers[approver] = authorized;
        emit ApproverAuthorizationUpdated(approver, authorized, block.timestamp);
    }

    // Function to transfer ownership (simulated via authorization)
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) {
            revert("New owner cannot be zero address");
        }
        authorizedApprovers[owner] = false; // Remove old owner as authorized approver
        authorizedApprovers[newOwner] = true; // New owner becomes authorized
        emit ApproverAuthorizationUpdated(newOwner, true, block.timestamp);
    }
}