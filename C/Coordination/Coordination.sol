// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IZKIdentityVerifier {
    function verifyIdentity(address voter, bytes memory zkProof) external view returns (bool);
}

contract CoordinationResistantVoting {
    IZKIdentityVerifier public zkVerifier;

    struct Proposal {
        string description;
        uint256 voteCount;
        bool active;
    }

    mapping(uint256 => Proposal) public proposals;
    mapping(address => bool) public hasVoted;

    uint256 public proposalCount;
    address public admin;

    event ProposalCreated(uint256 proposalId, string description);
    event VoteCasted(address voter, uint256 proposalId, uint256 votes);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    constructor(address _zkVerifier) {
        zkVerifier = IZKIdentityVerifier(_zkVerifier);
        admin = msg.sender;
    }

    function createProposal(string memory description) external onlyAdmin {
        proposalCount++;
        proposals[proposalCount] = Proposal(description, 0, true);
        emit ProposalCreated(proposalCount, description);
    }

    function quadraticVote(uint256 proposalId, uint256 votes, bytes memory zkProof) external {
        require(proposals[proposalId].active, "Proposal inactive");
        require(!hasVoted[msg.sender], "Already voted");
        require(zkVerifier.verifyIdentity(msg.sender, zkProof), "Identity verification failed");

        uint256 cost = votes * votes;
        proposals[proposalId].voteCount += votes;
        hasVoted[msg.sender] = true;

        emit VoteCasted(msg.sender, proposalId, votes);

        // Optional: Implement ERC20 token burn or payment logic here
    }

    function closeProposal(uint256 proposalId) external onlyAdmin {
        proposals[proposalId].active = false;
    }

    function getProposalVotes(uint256 proposalId) external view returns (uint256) {
        return proposals[proposalId].voteCount;
    }
}
