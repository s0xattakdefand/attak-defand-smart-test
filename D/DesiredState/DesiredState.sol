// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Importing OpenZeppelin contracts for security and standard patterns
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Context.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

// Smart contract for managing Desired State configurations
contract DesiredState is ReentrancyGuard, Ownable {
    // Struct to represent a team member (DevOps engineer or admin)
    struct TeamMember {
        address memberAddress;
        string name;
        bool isActive;
        uint256 joinDate;
    }

    // Struct to represent a configuration proposal
    struct ConfigProposal {
        uint256 id;
        address proposer;
        string title;
        string description;
        string ipfsHash; // Store configuration details (e.g., YAML, JSON) on IPFS
        uint256 voteCount;
        uint256 deadline;
        bool executed;
        bool approved;
        mapping(address => bool) hasVoted;
    }

    // State variables
    mapping(address => TeamMember) public teamMembers;
    mapping(uint256 => ConfigProposal) public proposals;
    uint256 public memberCount;
    uint256 public proposalCount;
    uint256 public constant VOTING_PERIOD = 7 days;
    uint256 public constant MINIMUM_QUORUM = 3; // Minimum votes needed to execute a proposal

    // Events for transparency
    event MemberAdded(address indexed member, string name, uint256 joinDate);
    event ProposalCreated(uint256 indexed proposalId, address indexed proposer, string title, string ipfsHash, uint256 deadline);
    event Voted(uint256 indexed proposalId, address indexed voter, uint256 voteCount);
    event ProposalExecuted(uint256 indexed proposalId, string title, bool approved, string ipfsHash);

    // Modifiers
    modifier onlyTeamMember() {
        require(teamMembers[_msgSender()].isActive, "Only active team members can perform this action");
        _;
    }

    // Constructor to set the deployer as the initial owner
    constructor() Ownable(msg.sender) {
        memberCount = 0;
        proposalCount = 0;
    }

    // Function to add a new team member (only owner can add members)
    function addTeamMember(address _memberAddress, string memory _name) external onlyOwner nonReentrant {
        require(_memberAddress != address(0), "Invalid address");
        require(!teamMembers[_memberAddress].isActive, "Member already exists");

        teamMembers[_memberAddress] = TeamMember({
            memberAddress: _memberAddress,
            name: _name,
            isActive: true,
            joinDate: block.timestamp
        });
        memberCount++;

        emit MemberAdded(_memberAddress, _name, block.timestamp);
    }

    // Function to create a new configuration proposal
    function createProposal(string memory _title, string memory _description, string memory _ipfsHash) external onlyTeamMember nonReentrant {
        require(bytes(_title).length > 0, "Title cannot be empty");
        require(bytes(_description).length > 0, "Description cannot be empty");
        require(bytes(_ipfsHash).length > 0, "IPFS hash cannot be empty");

        uint256 proposalId = proposalCount;
        ConfigProposal storage newProposal = proposals[proposalId];
        newProposal.id = proposalId;
        newProposal.proposer = _msgSender();
        newProposal.title = _title;
        newProposal.description = _description;
        newProposal.ipfsHash = _ipfsHash;
        newProposal.voteCount = 0;
        newProposal.deadline = block.timestamp + VOTING_PERIOD;
        newProposal.executed = false;
        newProposal.approved = false;

        proposalCount++;

        emit ProposalCreated(proposalId, _msgSender(), _title, _ipfsHash, newProposal.deadline);
    }

    // Function to vote on a configuration proposal
    function vote(uint256 _proposalId) external onlyTeamMember nonReentrant {
        ConfigProposal storage proposal = proposals[_proposalId];
        require(block.timestamp <= proposal.deadline, "Voting period has ended");
        require(!proposal.executed, "Proposal already executed");
        require(!proposal.hasVoted[_msgSender()], "Member has already voted");

        proposal.hasVoted[_msgSender()] = true;
        proposal.voteCount++;

        emit Voted(_proposalId, _msgSender(), proposal.voteCount);
    }

    // Function to execute a configuration proposal
    function executeProposal(uint256 _proposalId) external onlyTeamMember nonReentrant {
        ConfigProposal storage proposal = proposals[_proposalId];
        require(block.timestamp > proposal.deadline, "Voting period not ended");
        require(!proposal.executed, "Proposal already executed");
        require(proposal.voteCount >= MINIMUM_QUORUM, "Minimum quorum not reached");

        proposal.executed = true;
        proposal.approved = proposal.voteCount >= memberCount / 2 + 1; // Majority approval

        // If approved, the IPFS hash represents the new "desired state" to be applied
        emit ProposalExecuted(_proposalId, proposal.title, proposal.approved, proposal.ipfsHash);
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
        bool executed,
        bool approved
    ) {
        ConfigProposal storage proposal = proposals[_proposalId];
        require(proposal.proposer != address(0), "Proposal does not exist");
        return (
            proposal.id,
            proposal.proposer,
            proposal.title,
            proposal.description,
            proposal.ipfsHash,
            proposal.voteCount,
            proposal.deadline,
            proposal.executed,
            proposal.approved
        );
    }

    // Function to check if an address is a team member
    function isTeamMember(address _address) external view returns (bool) {
        return teamMembers[_address].isActive;
    }
}

// Notes:
// - This contract uses OpenZeppelin's ReentrancyGuard and Ownable for security.
// - IPFS hash stores configuration details (e.g., YAML/JSON files) off-chain to reduce gas costs.
// - The contract assumes a governance model where only the owner can add team members.
// - Proposals require a minimum quorum and majority vote to enforce a new desired state.
// - Events are emitted for transparency and auditability, enabling integration with off-chain DevOps tools.
// - Source code should be audited before deployment, preferably 2 weeks prior to mainnet use, as per industry standards (Webisoft, 2025).
// - Recommended to store source code on GitHub with a specific commit hash for audit purposes.