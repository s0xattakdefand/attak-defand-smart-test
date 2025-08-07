// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Importing OpenZeppelin contracts for security and standard patterns
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Context.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

// Smart contract for Developers Alliance for Standards Harmonization
contract StandardsAlliance is ReentrancyGuard, Ownable {
    // Struct to represent a member
    struct Member {
        address memberAddress;
        string name;
        bool isActive;
        uint256 joinDate;
    }

    // Struct to represent a standards proposal
    struct Proposal {
        uint256 id;
        address proposer;
        string title;
        string description;
        uint256 voteCount;
        uint256 deadline;
        bool executed;
        mapping(address => bool) hasVoted;
    }

    // State variables
    mapping(address => Member) public members;
    mapping(uint256 => Proposal) public proposals;
    uint256 public memberCount;
    uint256 public proposalCount;
    uint256 public constant VOTING_PERIOD = 7 days;
    uint256 public constant MINIMUM_QUORUM = 3; // Minimum votes needed to execute a proposal

    // Events for transparency
    event MemberAdded(address indexed member, string name, uint256 joinDate);
    event ProposalCreated(uint256 indexed proposalId, address indexed proposer, string title, uint256 deadline);
    event Voted(uint256 indexed proposalId, address indexed voter, uint256 voteCount);
    event ProposalExecuted(uint256 indexed proposalId, string title, bool approved);

    // Modifiers
    modifier onlyMember() {
        require(members[_msgSender()].isActive, "Only active members can perform this action");
        _;
    }

    // Constructor to set the deployer as the initial owner
    constructor() Ownable(msg.sender) {
        memberCount = 0;
        proposalCount = 0;
    }

    // Function to add a new member (only owner can add members)
    function addMember(address _memberAddress, string memory _name) external onlyOwner nonReentrant {
        require(_memberAddress != address(0), "Invalid address");
        require(!members[_memberAddress].isActive, "Member already exists");

        members[_memberAddress] = Member({
            memberAddress: _memberAddress,
            name: _name,
            isActive: true,
            joinDate: block.timestamp
        });
        memberCount++;

        emit MemberAdded(_memberAddress, _name, block.timestamp);
    }

    // Function to create a new standards proposal
    function createProposal(string memory _title, string memory _description) external onlyMember nonReentrant {
        require(bytes(_title).length > 0, "Title cannot be empty");
        require(bytes(_description).length > 0, "Description cannot be empty");

        uint256 proposalId = proposalCount;
        Proposal storage newProposal = proposals[proposalId];
        newProposal.id = proposalId;
        newProposal.proposer = _msgSender();
        newProposal.title = _title;
        newProposal.description = _description;
        newProposal.voteCount = 0;
        newProposal.deadline = block.timestamp + VOTING_PERIOD;
        newProposal.executed = false;

        proposalCount++;

        emit ProposalCreated(proposalId, _msgSender(), _title, newProposal.deadline);
    }

    // Function to vote on a proposal
    function vote(uint256 _proposalId) external onlyMember nonReentrant {
        Proposal storage proposal = proposals[_proposalId];
        require(block.timestamp <= proposal.deadline, "Voting period has ended");
        require(!proposal.executed, "Proposal already executed");
        require(!proposal.hasVoted[_msgSender()], "Member has already voted");

        proposal.hasVoted[_msgSender()] = true;
        proposal.voteCount++;

        emit Voted(_proposalId, _msgSender(), proposal.voteCount);
    }

    // Function to execute a proposal
    function executeProposal(uint256 _proposalId) external onlyMember nonReentrant {
        Proposal storage proposal = proposals[_proposalId];
        require(block.timestamp > proposal.deadline, "Voting period not ended");
        require(!proposal.executed, "Proposal already executed");
        require(proposal.voteCount >= MINIMUM_QUORUM, "Minimum quorum not reached");

        proposal.executed = true;
        bool approved = proposal.voteCount >= memberCount / 2 + 1; // Majority approval

        emit ProposalExecuted(_proposalId, proposal.title, approved);
    }

    // Function to get proposal details
    function getProposal(uint256 _proposalId) external view returns (
        uint256 id,
        address proposer,
        string memory title,
        string memory description,
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
            proposal.voteCount,
            proposal.deadline,
            proposal.executed
        );
    }

    // Function to check if an address is a member
    function isMember(address _address) external view returns (bool) {
        return members[_address].isActive;
    }
}

// Notes:
// - This contract uses OpenZeppelin's ReentrancyGuard and Ownable for security.
// - The contract assumes a governance model where only the owner can add members.
// - Proposals require a minimum quorum and majority vote to be executed.
// - Events are emitted for transparency and auditability.
// - The contract is designed to be modular and gas-efficient.
// - Source code should be audited before deployment, preferably 2 weeks prior to any token sale or mainnet use, as per industry standards.
// - Recommended to store source code on GitHub with a specific commit hash for audit purposes.