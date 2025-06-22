// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title VotingSystemQuorumAttackDefense - Full Attack and Defense Simulation for Voting Quorum Manipulation in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Secure voting contract protecting against quorum manipulation
contract SecureVotingSystem {
    address public owner;
    uint256 public votingPeriod = 3 days;
    uint256 public minQuorumPercent = 20; // Minimum % of voters required
    uint256 public proposalCounter;

    struct Proposal {
        string description;
        uint256 votesFor;
        uint256 votesAgainst;
        uint256 startTime;
        bool executed;
    }

    mapping(uint256 => Proposal) public proposals;
    mapping(address => bool) public registeredVoters;
    mapping(uint256 => mapping(address => bool)) public hasVoted;
    uint256 public totalVoters;

    event ProposalCreated(uint256 indexed proposalId, string description);
    event Voted(uint256 indexed proposalId, address indexed voter, bool support);
    event ProposalExecuted(uint256 indexed proposalId, bool passed);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function registerVoter(address voter) external onlyOwner {
        require(!registeredVoters[voter], "Already registered");
        registeredVoters[voter] = true;
        totalVoters += 1;
    }

    function createProposal(string calldata description) external onlyOwner returns (uint256) {
        proposalCounter++;
        proposals[proposalCounter] = Proposal({
            description: description,
            votesFor: 0,
            votesAgainst: 0,
            startTime: block.timestamp,
            executed: false
        });

        emit ProposalCreated(proposalCounter, description);
        return proposalCounter;
    }

    function vote(uint256 proposalId, bool support) external {
        require(registeredVoters[msg.sender], "Not registered");
        require(!hasVoted[proposalId][msg.sender], "Already voted");
        require(proposals[proposalId].startTime != 0, "Proposal doesn't exist");
        require(block.timestamp <= proposals[proposalId].startTime + votingPeriod, "Voting period over");

        if (support) {
            proposals[proposalId].votesFor += 1;
        } else {
            proposals[proposalId].votesAgainst += 1;
        }

        hasVoted[proposalId][msg.sender] = true;
        emit Voted(proposalId, msg.sender, support);
    }

    function executeProposal(uint256 proposalId) external {
        Proposal storage prop = proposals[proposalId];
        require(!prop.executed, "Already executed");
        require(block.timestamp > prop.startTime + votingPeriod, "Voting still active");

        uint256 totalVotes = prop.votesFor + prop.votesAgainst;
        uint256 quorumNeeded = (totalVoters * minQuorumPercent) / 100;

        require(totalVotes >= quorumNeeded, "Quorum not reached");

        prop.executed = true;
        bool passed = prop.votesFor > prop.votesAgainst;

        emit ProposalExecuted(proposalId, passed);
    }
}

/// @notice Attack contract trying to abuse low quorum
contract QuorumAttackIntruder {
    address public target;

    constructor(address _target) {
        target = _target;
    }

    function tryEarlyPass(uint256 proposalId) external returns (bool success) {
        (success, ) = target.call(
            abi.encodeWithSignature("executeProposal(uint256)", proposalId)
        );
    }
}
