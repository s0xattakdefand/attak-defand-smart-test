// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Importing OpenZeppelin contracts for security and standard patterns
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Context.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

// Smart contract for Developing the Curriculum
contract CurriculumDevelopment is ReentrancyGuard, Ownable {
    // Struct to represent an educator (member)
    struct Educator {
        address educatorAddress;
        string name;
        bool isActive;
        uint256 joinDate;
    }

    // Struct to represent a curriculum proposal
    struct Proposal {
        uint256 id;
        address proposer;
        string title;
        string description;
        string ipfsHash; // Store curriculum content on IPFS
        uint256 voteCount;
        uint256 deadline;
        bool executed;
        mapping(address => bool) hasVoted;
    }

    // State variables
    mapping(address => Educator) public educators;
    mapping(uint256 => Proposal) public proposals;
    uint256 public educatorCount;
    uint256 public proposalCount;
    uint256 public constant VOTING_PERIOD = 7 days;
    uint256 public constant MINIMUM_QUORUM = 3; // Minimum votes needed to execute a proposal

    // Events for transparency
    event EducatorAdded(address indexed educator, string name, uint256 joinDate);
    event ProposalCreated(uint256 indexed proposalId, address indexed proposer, string title, string ipfsHash, uint256 deadline);
    event Voted(uint256 indexed proposalId, address indexed voter, uint256 voteCount);
    event ProposalExecuted(uint256 indexed proposalId, string title, bool approved);

    // Modifiers
    modifier onlyEducator() {
        require(educators[_msgSender()].isActive, "Only active educators can perform this action");
        _;
    }

    // Constructor to set the deployer as the initial owner
    constructor() Ownable(msg.sender) {
        educatorCount = 0;
        proposalCount = 0;
    }

    // Function to add a new educator (only owner can add educators)
    function addEducator(address _educatorAddress, string memory _name) external onlyOwner nonReentrant {
        require(_educatorAddress != address(0), "Invalid address");
        require(!educators[_educatorAddress].isActive, "Educator already exists");

        educators[_educatorAddress] = Educator({
            educatorAddress: _educatorAddress,
            name: _name,
            isActive: true,
            joinDate: block.timestamp
        });
        educatorCount++;

        emit EducatorAdded(_educatorAddress, _name, block.timestamp);
    }

    // Function to create a new curriculum proposal
    function createProposal(string memory _title, string memory _description, string memory _ipfsHash) external onlyEducator nonReentrant {
        require(bytes(_title).length > 0, "Title cannot be empty");
        require(bytes(_description).length > 0, "Description cannot be empty");
        require(bytes(_ipfsHash).length > 0, "IPFS hash cannot be empty");

        uint256 proposalId = proposalCount;
        Proposal storage newProposal = proposals[proposalId];
        newProposal.id = proposalId;
        newProposal.proposer = _msgSender();
        newProposal.title = _title;
        newProposal.description = _description;
        newProposal.ipfsHash = _ipfsHash;
        newProposal.voteCount = 0;
        newProposal.deadline = block.timestamp + VOTING_PERIOD;
        newProposal.executed = false;

        proposalCount++;

        emit ProposalCreated(proposalId, _msgSender(), _title, _ipfsHash, newProposal.deadline);
    }

    // Function to vote on a proposal
    function vote(uint256 _proposalId) external onlyEducator nonReentrant {
        Proposal storage proposal = proposals[_proposalId];
        require(block.timestamp <= proposal.deadline, "Voting period has ended");
        require(!proposal.executed, "Proposal already executed");
        require(!proposal.hasVoted[_msgSender()], "Educator has already voted");

        proposal.hasVoted[_msgSender()] = true;
        proposal.voteCount++;

        emit Voted(_proposalId, _msgSender(), proposal.voteCount);
    }

    // Function to execute a proposal
    function executeProposal(uint256 _proposalId) external onlyEducator nonReentrant {
        Proposal storage proposal = proposals[_proposalId];
        require(block.timestamp > proposal.deadline, "Voting period not ended");
        require(!proposal.executed, "Proposal already executed");
        require(proposal.voteCount >= MINIMUM_QUORUM, "Minimum quorum not reached");

        proposal.executed = true;
        bool approved = proposal.voteCount >= educatorCount / 2 + 1; // Majority approval

        emit ProposalExecuted(_proposalId, proposal.title, approved);
    }

    // Function to get proposal details
    function getProposal(uint256 _proposalId) external view returns (
        uint256 id,
        address proposer,
        string memory title,
        string memory description,
        string memory ipfsHash,
        uint256 voteCount,
        uint256 deadline,
        bool executed
    ) {
        Proposal storage proposal = proposals[_proposalId];
        return (
            proposal.id,
            proposal.proposer,
            proposal.title,
            proposal.description,
            proposal.ipfsHash,
            proposal.voteCount,
            proposal.deadline,
            proposal.executed
        );
    }

    // Function to check if an address is an educator
    function isEducator(address _address) external view returns (bool) {
        return educators[_address].isActive;
    }
}

// Notes:
// - This contract uses OpenZeppelin's ReentrancyGuard and Ownable for security.
// - IPFS hash is included to store detailed curriculum content off-chain, reducing gas costs.
// - The contract assumes a governance model where only the owner can add educators.
// - Proposals require a minimum quorum and majority vote to be executed.
// - Events are emitted for transparency and auditability.
// - Source code should be audited before deployment, preferably 2 weeks prior to any mainnet use, as per industry standards.
// - Recommended to store source code on GitHub with a specific commit hash for audit purposes.