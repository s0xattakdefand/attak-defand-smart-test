// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AFRLDAO — Air Force Research Lab DAO simulation in Web3
contract AFRLDAO {
    address public commander;

    enum Status { PENDING, APPROVED, FUNDED, COMPLETED }

    struct Proposal {
        string title;
        string domain;           // e.g., "Cyber", "Aerospace", "ZK-Simulation"
        string uri;              // IPFS report or spec
        address proposer;
        Status status;
        uint256 requestedFunding;
        uint256 releasedFunding;
        uint256 timestamp;
    }

    Proposal[] public proposals;
    mapping(address => uint256[]) public byProposer;

    event ProposalSubmitted(uint256 id, string title, string domain);
    event ProposalApproved(uint256 id, uint256 amount);
    event MilestoneVerified(uint256 id, uint256 trancheReleased);
    event ProposalCompleted(uint256 id);

    modifier onlyCommander() {
        require(msg.sender == commander, "Unauthorized");
        _;
    }

    constructor() {
        commander = msg.sender;
    }

    function submitProposal(string calldata title, string calldata domain, string calldata uri, uint256 funding) external returns (uint256) {
        proposals.push(Proposal(title, domain, uri, msg.sender, Status.PENDING, funding, 0, block.timestamp));
        uint256 id = proposals.length - 1;
        byProposer[msg.sender].push(id);
        emit ProposalSubmitted(id, title, domain);
        return id;
    }

    function approveProposal(uint256 id) external onlyCommander {
        Proposal storage p = proposals[id];
        require(p.status == Status.PENDING, "Already processed");
        p.status = Status.APPROVED;
        emit ProposalApproved(id, p.requestedFunding);
    }

    function releaseMilestone(uint256 id, uint256 amount) external onlyCommander {
        Proposal storage p = proposals[id];
        require(p.status == Status.APPROVED || p.status == Status.FUNDED, "Not approved yet");
        p.releasedFunding += amount;
        p.status = Status.FUNDED;
        emit MilestoneVerified(id, amount);
    }

    function markCompleted(uint256 id) external onlyCommander {
        Proposal storage p = proposals[id];
        p.status = Status.COMPLETED;
        emit ProposalCompleted(id);
    }

    function getProposal(uint256 id) external view returns (Proposal memory) {
        return proposals[id];
    }

    function getProposalsBy(address user) external view returns (uint256[] memory) {
        return byProposer[user];
    }
}
