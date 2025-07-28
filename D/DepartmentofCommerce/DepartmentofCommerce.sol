// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// DepartmentOfCommerce contract for managing procurement/grant opportunities
contract DepartmentOfCommerce {
    // Contract owner (e.g., Department of Commerce representative)
    address public owner;

    // Structure to store procurement/grant opportunity details
    struct Opportunity {
        bytes32 opportunityId; // Unique identifier for the opportunity
        string description; // Description of the opportunity (e.g., grant or contract details)
        uint256 submissionDeadline; // Deadline for proposal submissions
        uint256 maxFunding; // Maximum funding amount (in wei)
        address awardedTo; // Address of the awarded entity (if any)
        bool active; // Whether the opportunity is active
        uint256 createdAt; // Timestamp when opportunity was created
    }

    // Structure to store proposal details
    struct Proposal {
        bytes32 opportunityId; // Associated opportunity ID
        address submitter; // Address of the entity submitting the proposal
        string proposalURI; // Off-chain URI for proposal details (e.g., IPFS link)
        bool exists; // Flag to check if proposal exists
        uint256 submittedAt; // Timestamp when proposal was submitted
    }

    // Structure to store submission metadata for rate limiting
    struct SubmissionInfo {
        uint256 lastSubmissionTimestamp; // Timestamp of last submission
        uint256 submissionCount; // Number of submissions in current window
    }

    // Mapping to store opportunities by opportunity ID
    mapping(bytes32 => Opportunity) public opportunities;

    // Mapping to store proposals by opportunity ID and submitter address
    mapping(bytes32 => mapping(address => Proposal)) public proposals;

    // Mapping to store authorized submitters (e.g., eligible vendors or grantees)
    mapping(address => bool) public authorizedSubmitters;

    // Mapping to store submission metadata for rate limiting
    mapping(address => SubmissionInfo) public submissionInfo;

    // Rate limit parameters to prevent DoS
    uint256 public constant SUBMISSION_WINDOW = 1 hours; // Time window for rate limiting
    uint256 public constant MAX_SUBMISSIONS_PER_WINDOW = 5; // Max submissions per window
    uint256 public constant MIN_SUBMISSION_INTERVAL = 10 seconds; // Minimum time between submissions

    // Event emitted when an opportunity is created
    event OpportunityCreated(bytes32 indexed opportunityId, string description, uint256 submissionDeadline, uint256 maxFunding, uint256 timestamp);

    // Event emitted when a proposal is submitted
    event ProposalSubmitted(bytes32 indexed opportunityId, address indexed submitter, string proposalURI, uint256 timestamp);

    // Event emitted when an opportunity is awarded
    event OpportunityAwarded(bytes32 indexed opportunityId, address indexed awardedTo, uint256 fundingAmount, uint256 timestamp);

    // Event emitted when a submitter is authorized or deauthorized
    event SubmitterAuthorizationUpdated(address indexed submitter, bool authorized, uint256 timestamp);

    // Event emitted when rate limit is triggered
    event RateLimitTriggered(address indexed submitter, uint256 timestamp);

    // Event emitted when funds are deposited
    event FundsDeposited(address indexed sender, uint256 amount, uint256 timestamp);

    // Modifier to restrict functions to the contract owner
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    // Modifier to restrict functions to authorized submitters
    modifier onlyAuthorizedSubmitter() {
        require(authorizedSubmitters[msg.sender], "Only authorized submitters can call this function");
        _;
    }

    // Modifier to check if an opportunity exists and is active
    modifier opportunityActive(bytes32 opportunityId) {
        require(opportunities[opportunityId].active, "Opportunity not active or does not exist");
        require(block.timestamp <= opportunities[opportunityId].submissionDeadline, "Submission deadline passed");
        _;
    }

    // Constructor to set the owner
    constructor() {
        owner = msg.sender;
        authorizedSubmitters[msg.sender] = true; // Owner is an authorized submitter by default
    }

    // Function to create a new procurement/grant opportunity
    function createOpportunity(
        bytes32 opportunityId,
        string calldata description,
        uint256 submissionDeadline,
        uint256 maxFunding
    ) external onlyOwner {
        require(!opportunities[opportunityId].active, "Opportunity ID already exists");
        require(submissionDeadline > block.timestamp, "Submission deadline must be in the future");
        require(maxFunding > 0, "Max funding must be greater than zero");
        require(bytes(description).length <= 500, "Description too long"); // Bound input size

        opportunities[opportunityId] = Opportunity({
            opportunityId: opportunityId,
            description: description,
            submissionDeadline: submissionDeadline,
            maxFunding: maxFunding,
            awardedTo: address(0),
            active: true,
            createdAt: block.timestamp
        });

        emit OpportunityCreated(opportunityId, description, submissionDeadline, maxFunding, block.timestamp);
    }

    // Function to submit a proposal for an opportunity
    function submitProposal(bytes32 opportunityId, string calldata proposalURI)
        external
        onlyAuthorizedSubmitter
        opportunityActive(opportunityId)
    {
        require(!proposals[opportunityId][msg.sender].exists, "Proposal already submitted");
        require(bytes(proposalURI).length <= 200, "Proposal URI too long"); // Bound input size

        // Rate limiting
        SubmissionInfo storage submitterInfo = submissionInfo[msg.sender];
        if (block.timestamp >= submitterInfo.lastSubmissionTimestamp + SUBMISSION_WINDOW) {
            submitterInfo.submissionCount = 0;
            submitterInfo.lastSubmissionTimestamp = block.timestamp;
        } else {
            require(
                block.timestamp >= submitterInfo.lastSubmissionTimestamp + MIN_SUBMISSION_INTERVAL,
                "Submission interval too short"
            );
            require(submitterInfo.submissionCount < MAX_SUBMISSIONS_PER_WINDOW, "Submission limit exceeded");
            emit RateLimitTriggered(msg.sender, block.timestamp);
        }

        submitterInfo.submissionCount += 1;

        proposals[opportunityId][msg.sender] = Proposal({
            opportunityId: opportunityId,
            submitter: msg.sender,
            proposalURI: proposalURI,
            exists: true,
            submittedAt: block.timestamp
        });

        emit ProposalSubmitted(opportunityId, msg.sender, proposalURI, block.timestamp);
    }

    // Function to award an opportunity and distribute funds
    function awardOpportunity(bytes32 opportunityId, address awardee, uint256 fundingAmount)
        external
        onlyOwner
        opportunityActive(opportunityId)
    {
        require(awardee != address(0), "Awardee cannot be zero address");
        require(proposals[opportunityId][awardee].exists, "Awardee has not submitted a proposal");
        require(fundingAmount <= opportunities[opportunityId].maxFunding, "Funding amount exceeds maximum");
        require(fundingAmount <= address(this).balance, "Insufficient contract balance");

        opportunities[opportunityId].awardedTo = awardee;
        opportunities[opportunityId].active = false; // Close the opportunity

        // Transfer funds to the awardee
        (bool success, ) = awardee.call{value: fundingAmount}("");
        require(success, "Funding transfer failed");

        emit OpportunityAwarded(opportunityId, awardee, fundingAmount, block.timestamp);
    }

    // Function to authorize or deauthorize a submitter
    function setSubmitterAuthorization(address submitter, bool authorized) external onlyOwner {
        require(submitter != address(0), "Submitter cannot be zero address");
        require(authorizedSubmitters[submitter] != authorized, "Authorization status already set");

        authorizedSubmitters[submitter] = authorized;
        emit SubmitterAuthorizationUpdated(submitter, authorized, block.timestamp);
    }

    // Function to get opportunity details
    function getOpportunityDetails(bytes32 opportunityId)
        external
        view
        returns (
            string memory description,
            uint256 submissionDeadline,
            uint256 maxFunding,
            address awardedTo,
            bool active,
            uint256 createdAt
        )
    {
        require(opportunities[opportunityId].active || opportunities[opportunityId].createdAt > 0, "Opportunity does not exist");

        Opportunity memory opp = opportunities[opportunityId];
        return (
            opp.description,
            opp.submissionDeadline,
            opp.maxFunding,
            opp.awardedTo,
            opp.active,
            opp.createdAt
        );
    }

    // Function to get proposal details
    function getProposalDetails(bytes32 opportunityId, address submitter)
        external
        view
        returns (
            string memory proposalURI,
            uint256 submittedAt
        )
    {
        require(proposals[opportunityId][submitter].exists, "Proposal does not exist");
        require(
            msg.sender == owner ||
            msg.sender == submitter ||
            authorizedSubmitters[msg.sender],
            "Not authorized to view proposal details"
        );

        Proposal memory prop = proposals[opportunityId][submitter];
        return (prop.proposalURI, prop.submittedAt);
    }

    // Function to transfer ownership
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "New owner cannot be zero address");
        authorizedSubmitters[owner] = false; // Remove old owner as authorized submitter
        owner = newOwner;
        authorizedSubmitters[newOwner] = true; // New owner becomes an authorized submitter
        emit SubmitterAuthorizationUpdated(newOwner, true, block.timestamp);
    }

    // Fallback function to receive Ether (e.g., for funding opportunities)
    receive() external payable {
        emit FundsDeposited(msg.sender, msg.value, block.timestamp);
    }
}