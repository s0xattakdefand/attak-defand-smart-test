// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title HostileGovernanceTakeoverAttackDefense - Attack and Defense Simulation for Rug Pull Protection in Web3 Governance Systems
/// @author ChatGPT

/// @notice Secure governance contract preventing hostile takeovers
contract SecureGovernanceSystem {
    address public guardian;
    uint256 public proposalCounter;
    uint256 public minDelay = 2 days;
    uint256 public minVotesToPass = 1000; // Example: Require 1000 votes minimum
    uint256 public emergencyVetoTimeWindow = 1 days;

    struct Proposal {
        string description;
        address target;
        uint256 votesFor;
        uint256 votesAgainst;
        uint256 snapshotVotingPower;
        uint256 startTime;
        bool executed;
        bool vetoed;
    }

    mapping(uint256 => Proposal) public proposals;
    mapping(address => uint256) public votingPower;
    mapping(uint256 => mapping(address => bool)) public hasVoted;

    event ProposalCreated(uint256 indexed id, string description);
    event Voted(uint256 indexed id, address indexed voter, bool support);
    event ProposalVetoed(uint256 indexed id);
    event ProposalExecuted(uint256 indexed id);

    modifier onlyGuardian() {
        require(msg.sender == guardian, "Not guardian");
        _;
    }

    constructor(address _guardian) {
        guardian = _guardian;
        votingPower[msg.sender] = 10000; // Genesis voter (initial voting power)
    }

    function assignVotingPower(address voter, uint256 amount) external onlyGuardian {
        votingPower[voter] = amount;
    }

    function createProposal(string calldata description, address _target) external returns (uint256) {
        proposalCounter++;
        proposals[proposalCounter] = Proposal({
            description: description,
            target: _target,
            votesFor: 0,
            votesAgainst: 0,
            snapshotVotingPower: totalVotingPower(),
            startTime: block.timestamp,
            executed: false,
            vetoed: false
        });

        emit ProposalCreated(proposalCounter, description);
        return proposalCounter;
    }

    function vote(uint256 proposalId, bool support) external {
        require(proposals[proposalId].startTime > 0, "Invalid proposal");
        require(!hasVoted[proposalId][msg.sender], "Already voted");
        require(votingPower[msg.sender] > 0, "No voting power");

        hasVoted[proposalId][msg.sender] = true;

        if (support) {
            proposals[proposalId].votesFor += votingPower[msg.sender];
        } else {
            proposals[proposalId].votesAgainst += votingPower[msg.sender];
        }

        emit Voted(proposalId, msg.sender, support);
    }

    function vetoProposal(uint256 proposalId) external onlyGuardian {
        Proposal storage prop = proposals[proposalId];
        require(block.timestamp <= prop.startTime + emergencyVetoTimeWindow, "Veto window expired");
        require(!prop.executed, "Already executed");
        prop.vetoed = true;

        emit ProposalVetoed(proposalId);
    }

    function executeProposal(uint256 proposalId) external {
        Proposal storage prop = proposals[proposalId];
        require(!prop.executed, "Already executed");
        require(!prop.vetoed, "Vetoed proposal");
        require(block.timestamp > prop.startTime + minDelay, "Delay not passed");

        uint256 totalVotes = prop.votesFor + prop.votesAgainst;
        require(totalVotes >= prop.snapshotVotingPower / 2, "Not enough votes");
        require(prop.votesFor > prop.votesAgainst, "Proposal rejected");

        prop.executed = true;

        (bool success, ) = prop.target.call(""); // Example: empty call (normally upgrade or treasury withdrawal logic)
        require(success, "Target call failed");

        emit ProposalExecuted(proposalId);
    }

    function totalVotingPower() public view returns (uint256 power) {
        // For simplicity, simulate static total voting power
        return 10000;
    }
}

/// @notice Attack contract trying to pass hostile proposal quickly
contract GovernanceTakeoverIntruder {
    address public target;

    constructor(address _target) {
        target = _target;
    }

    function tryHostilePass(uint256 proposalId) external returns (bool success) {
        (success, ) = target.call(
            abi.encodeWithSignature("executeProposal(uint256)", proposalId)
        );
    }
}
