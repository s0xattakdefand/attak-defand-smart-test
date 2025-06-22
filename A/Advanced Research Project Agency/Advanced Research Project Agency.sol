// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Advanced Research Project Agency (ARPA) — R&D Funding & Milestone Tracker
contract ARPAAgency {
    address public director;

    enum Status { Proposed, Approved, InProgress, Completed, Cancelled }

    struct Proposal {
        string title;
        string description;
        address proposer;
        uint256 fundingRequested;
        Status status;
        uint256 timestamp;
    }

    Proposal[] public proposals;
    mapping(uint256 => string[]) public milestones;

    event ProposalSubmitted(uint256 indexed id, string title);
    event ProposalStatusChanged(uint256 indexed id, Status newStatus);
    event MilestoneAdded(uint256 indexed id, string milestone);

    modifier onlyDirector() {
        require(msg.sender == director, "Only director");
        _;
    }

    constructor() {
        director = msg.sender;
    }

    function submitProposal(
        string calldata title,
        string calldata description,
        uint256 fundingRequested
    ) external returns (uint256) {
        proposals.push(Proposal(title, description, msg.sender, fundingRequested, Status.Proposed, block.timestamp));
        uint256 id = proposals.length - 1;
        emit ProposalSubmitted(id, title);
        return id;
    }

    function changeStatus(uint256 id, Status newStatus) external onlyDirector {
        proposals[id].status = newStatus;
        emit ProposalStatusChanged(id, newStatus);
    }

    function addMilestone(uint256 id, string calldata milestone) external onlyDirector {
        milestones[id].push(milestone);
        emit MilestoneAdded(id, milestone);
    }

    function getProposal(uint256 id) external view returns (Proposal memory) {
        return proposals[id];
    }

    function getMilestones(uint256 id) external view returns (string[] memory) {
        return milestones[id];
    }

    function totalProposals() external view returns (uint256) {
        return proposals.length;
    }
}
