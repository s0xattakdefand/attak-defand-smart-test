// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title GovernmentForBusinessAttackDefense - Full Attack and Defense Simulation for Web3 Governance for Business Smart Contracts
/// @author ChatGPT

/// @notice Insecure Governance (Centralized Admin Vulnerable to Abuse)
contract InsecureBusinessGovernance {
    address public admin;
    mapping(address => uint256) public votes;

    event ProposalExecuted(string description);

    constructor() {
        admin = msg.sender;
    }

    function submitProposal(string memory description) external {
        require(msg.sender == admin, "Only admin can submit");
        emit ProposalExecuted(description);
        // BAD: No community voting required.
    }

    function adminChange(address newAdmin) external {
        require(msg.sender == admin, "Only admin");
        admin = newAdmin; // BAD: No multisig or quorum check.
    }
}

/// @notice Secure Business Governance (Community-Driven with Defense Controls)
contract SecureBusinessGovernance {
    address public immutable deployer;
    uint256 public quorumPercentage; // minimum % of total votes
    uint256 public proposalDelay; // time delay for execution
    uint256 public totalVotes;

    struct Proposal {
        string description;
        uint256 voteCount;
        uint256 creationTime;
        bool executed;
    }

    mapping(uint256 => Proposal) public proposals;
    mapping(address => uint256) public voterWeights;
    mapping(uint256 => mapping(address => bool)) public hasVoted;
    uint256 public proposalCounter;

    event ProposalCreated(uint256 indexed id, string description);
    event Voted(uint256 indexed id, address indexed voter, uint256 weight);
    event ProposalExecuted(uint256 indexed id, string description);

    constructor(uint256 _quorumPercentage, uint256 _proposalDelay) {
        deployer = msg.sender;
        quorumPercentage = _quorumPercentage;
        proposalDelay = _proposalDelay;
    }

    function registerVoter(address voter, uint256 weight) external {
        require(msg.sender == deployer, "Only deployer");
        voterWeights[voter] = weight;
        totalVotes += weight;
    }

    function createProposal(string memory description) external returns (uint256) {
        proposalCounter++;
        proposals[proposalCounter] = Proposal(description, 0, block.timestamp, false);
        emit ProposalCreated(proposalCounter, description);
        return proposalCounter;
    }

    function vote(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];
        require(!hasVoted[proposalId][msg.sender], "Already voted");
        require(!p.executed, "Already executed");

        uint256 weight = voterWeights[msg.sender];
        require(weight > 0, "Not eligible");

        p.voteCount += weight;
        hasVoted[proposalId][msg.sender] = true;

        emit Voted(proposalId, msg.sender, weight);
    }

    function executeProposal(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];
        require(!p.executed, "Already executed");
        require(block.timestamp >= p.creationTime + proposalDelay, "Delay not passed");

        uint256 requiredVotes = (totalVotes * quorumPercentage) / 100;
        require(p.voteCount >= requiredVotes, "Quorum not reached");

        p.executed = true;
        emit ProposalExecuted(proposalId, p.description);
    }
}

/// @notice Attack contract trying to abuse centralized governance
contract GovernanceIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function hijackControl(address newAdmin) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("adminChange(address)", newAdmin)
        );
    }
}
