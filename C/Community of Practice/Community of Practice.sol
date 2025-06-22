// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IZKIdentityVerifier {
    function verify(address user, bytes memory zkProof) external view returns (bool);
}

contract CommunityOfPractice {
    address public admin;
    IZKIdentityVerifier public zkVerifier;

    uint256 public proposalCount;

    struct Proposal {
        string description;
        uint256 totalVotes;
        bool active;
        mapping(address => bool) voted;
    }

    mapping(uint256 => Proposal) public proposals;
    mapping(address => bool) public verifiedMembers;

    event MemberVerified(address member);
    event ProposalCreated(uint256 proposalId, string description);
    event Voted(address voter, uint256 proposalId, uint256 votes);
    event ProposalClosed(uint256 proposalId);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Unauthorized: admin only");
        _;
    }

    modifier onlyVerified(address member, bytes memory proof) {
        require(zkVerifier.verify(member, proof), "Identity verification failed");
        _;
    }

    constructor(address _zkVerifier) {
        admin = msg.sender;
        zkVerifier = IZKIdentityVerifier(_zkVerifier);
    }

    // Admin manually verifies members (optional)
    function verifyMember(address member) external onlyAdmin {
        verifiedMembers[member] = true;
        emit MemberVerified(member);
    }

    // Create new community proposal
    function createProposal(string memory description) external onlyAdmin {
        proposalCount++;
        Proposal storage p = proposals[proposalCount];
        p.description = description;
        p.totalVotes = 0;
        p.active = true;

        emit ProposalCreated(proposalCount, description);
    }

    // Quadratic voting with zk-proof-based verification
    function voteOnProposal(uint256 proposalId, uint256 votes, bytes memory zkProof) external onlyVerified(msg.sender, zkProof) {
        Proposal storage p = proposals[proposalId];
        require(p.active, "Proposal is not active");
        require(!p.voted[msg.sender], "Already voted");

        uint256 voteWeight = votes * votes; // quadratic cost (handled off-chain typically)

        p.totalVotes += votes;
        p.voted[msg.sender] = true;

        emit Voted(msg.sender, proposalId, votes);

        // Additional token burn or economic logic can be added here
    }

    // Close proposal after voting period
    function closeProposal(uint256 proposalId) external onlyAdmin {
        Proposal storage p = proposals[proposalId];
        require(p.active, "Already closed");
        p.active = false;

        emit ProposalClosed(proposalId);
    }

    // Get proposal details
    function getProposal(uint256 proposalId) external view returns (string memory, uint256, bool) {
        Proposal storage p = proposals[proposalId];
        return (p.description, p.totalVotes, p.active);
    }
}
