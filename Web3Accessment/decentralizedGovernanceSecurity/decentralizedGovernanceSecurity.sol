// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title DecentralizedGovernanceSecurityAttackDefense - Full Attack and Defense Simulation for Governance Security in Web3 Smart Contracts
/// @author ChatGPT

interface IERC20Votes {
    function getPastVotes(address account, uint256 blockNumber) external view returns (uint256);
    function totalSupply() external view returns (uint256);
}

/// @notice Secure Governance Contract Protecting Against Takeover, Bribery, and Emergency Upgrades
contract SecureDecentralizedGovernance {
    address public owner;
    IERC20Votes public governanceToken;
    uint256 public proposalCounter;
    uint256 public minVotingPeriod = 3 days;
    uint256 public minQuorumPercent = 20;
    address public guardian;
    uint256 public emergencyVetoWindow = 1 days;

    struct Proposal {
        string description;
        address target;
        uint256 votesFor;
        uint256 votesAgainst;
        uint256 createdAt;
        uint256 snapshotBlock;
        bool executed;
        bool vetoed;
    }

    mapping(uint256 => Proposal) public proposals;
    mapping(uint256 => mapping(address => bool)) public hasVoted;

    event ProposalCreated(uint256 indexed id, address indexed proposer, string description);
    event Voted(uint256 indexed id, address indexed voter, bool support);
    event ProposalExecuted(uint256 indexed id);
    event ProposalVetoed(uint256 indexed id);

    modifier onlyGuardian() {
        require(msg.sender == guardian, "Not guardian");
        _;
    }

    constructor(address _governanceToken, address _guardian) {
        governanceToken = IERC20Votes(_governanceToken);
        guardian = _guardian;
        owner = msg.sender;
    }

    function createProposal(string calldata description, address target) external returns (uint256) {
        proposalCounter++;
        proposals[proposalCounter] = Proposal({
            description: description,
            target: target,
            votesFor: 0,
            votesAgainst: 0,
            createdAt: block.timestamp,
            snapshotBlock: block.number,
            executed: false,
            vetoed: false
        });

        emit ProposalCreated(proposalCounter, msg.sender, description);
        return proposalCounter;
    }

    function vote(uint256 proposalId, bool support) external {
        Proposal storage prop = proposals[proposalId];
        require(block.timestamp <= prop.createdAt + minVotingPeriod, "Voting closed");
        require(!hasVoted[proposalId][msg.sender], "Already voted");

        uint256 votes = governanceToken.getPastVotes(msg.sender, prop.snapshotBlock);
        require(votes > 0, "No voting power");

        if (support) {
            prop.votesFor += votes;
        } else {
            prop.votesAgainst += votes;
        }

        hasVoted[proposalId][msg.sender] = true;
        emit Voted(proposalId, msg.sender, support);
    }

    function vetoProposal(uint256 proposalId) external onlyGuardian {
        Proposal storage prop = proposals[proposalId];
        require(block.timestamp <= prop.createdAt + emergencyVetoWindow, "Veto window expired");
        require(!prop.executed, "Already executed");
        prop.vetoed = true;
        emit ProposalVetoed(proposalId);
    }

    function executeProposal(uint256 proposalId) external {
        Proposal storage prop = proposals[proposalId];
        require(!prop.executed, "Already executed");
        require(!prop.vetoed, "Vetoed proposal");
        require(block.timestamp > prop.createdAt + minVotingPeriod, "Voting still ongoing");

        uint256 totalSupply = governanceToken.totalSupply();
        uint256 totalVotes = prop.votesFor + prop.votesAgainst;
        uint256 quorumNeeded = (totalSupply * minQuorumPercent) / 100;

        require(totalVotes >= quorumNeeded, "Quorum not reached");
        require(prop.votesFor > prop.votesAgainst, "Proposal rejected");

        prop.executed = true;

        // Execute target logic (simulation, usually upgrade/treasury operation)
        (bool success, ) = prop.target.call("");
        require(success, "Target call failed");

        emit ProposalExecuted(proposalId);
    }
}

/// @notice Attack contract simulating flashloan boosted governance attack
contract GovernanceTakeoverIntruder {
    address public target;
    IERC20Votes public token;

    constructor(address _target, address _token) {
        target = _target;
        token = IERC20Votes(_token);
    }

    function simulateFlashloanVote(uint256 proposalId) external {
        // In real attack, borrow governance tokens, vote, return.
        // Here: Assume caller has flashloaned tokens already.
        (bool success, ) = target.call(
            abi.encodeWithSignature("vote(uint256,bool)", proposalId, true)
        );
        require(success, "Vote failed");
    }
}
