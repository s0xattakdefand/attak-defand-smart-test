// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// ASMS Conference Registry and Voting System
contract ASMSConference {
    address public chair;

    enum Status { Submitted, Accepted, Rejected }

    struct Proposal {
        string title;
        string author;
        string ipfsCID; // IPFS link to paper/media
        uint256 voteCount;
        Status status;
        uint256 timestamp;
    }

    Proposal[] public proposals;
    mapping(uint256 => mapping(address => bool)) public voted;

    event ProposalSubmitted(uint256 indexed id, string title);
    event Voted(uint256 indexed id, address voter);
    event StatusChanged(uint256 indexed id, Status newStatus);

    modifier onlyChair() {
        require(msg.sender == chair, "Not chair");
        _;
    }

    constructor() {
        chair = msg.sender;
    }

    function submitProposal(
        string calldata title,
        string calldata author,
        string calldata ipfsCID
    ) external returns (uint256) {
        proposals.push(Proposal(title, author, ipfsCID, 0, Status.Submitted, block.timestamp));
        uint256 id = proposals.length - 1;
        emit ProposalSubmitted(id, title);
        return id;
    }

    function voteOnProposal(uint256 id) external {
        require(!voted[id][msg.sender], "Already voted");
        proposals[id].voteCount += 1;
        voted[id][msg.sender] = true;
        emit Voted(id, msg.sender);
    }

    function finalizeStatus(uint256 id, bool accept) external onlyChair {
        proposals[id].status = accept ? Status.Accepted : Status.Rejected;
        emit StatusChanged(id, proposals[id].status);
    }

    function getProposal(uint256 id) external view returns (Proposal memory) {
        return proposals[id];
    }

    function totalProposals() external view returns (uint256) {
        return proposals.length;
    }
}
