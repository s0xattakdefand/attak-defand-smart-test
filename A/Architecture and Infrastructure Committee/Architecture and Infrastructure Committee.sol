// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract AICGovernanceCore {
    address public chair;
    mapping(address => bool) public isCommitteeMember;
    uint256 public quorumRequired = 2;

    struct Proposal {
        string description;
        address target;
        bool approved;
        uint256 approvals;
        mapping(address => bool) voted;
    }

    uint256 public proposalCount;
    mapping(uint256 => Proposal) public proposals;
    mapping(address => bool) public pausedTargets;

    event MemberAdded(address indexed member);
    event ProposalCreated(uint256 indexed id, address target, string desc);
    event ProposalApproved(uint256 indexed id, address indexed voter);
    event InfrastructurePaused(address indexed target);

    modifier onlyChair() {
        require(msg.sender == chair, "Not chair");
        _;
    }

    modifier onlyCommittee() {
        require(isCommitteeMember[msg.sender], "Not committee member");
        _;
    }

    constructor(address[] memory initialMembers) {
        chair = msg.sender;
        for (uint i = 0; i < initialMembers.length; i++) {
            isCommitteeMember[initialMembers[i]] = true;
            emit MemberAdded(initialMembers[i]);
        }
    }

    function addCommitteeMember(address member) external onlyChair {
        isCommitteeMember[member] = true;
        emit MemberAdded(member);
    }

    function createProposal(string calldata desc, address target) external onlyCommittee returns (uint256) {
        uint256 id = ++proposalCount;
        Proposal storage p = proposals[id];
        p.description = desc;
        p.target = target;
        emit ProposalCreated(id, target, desc);
        return id;
    }

    function approveProposal(uint256 id) external onlyCommittee {
        Proposal storage p = proposals[id];
        require(!p.voted[msg.sender], "Already voted");
        require(!p.approved, "Already approved");

        p.approvals += 1;
        p.voted[msg.sender] = true;

        if (p.approvals >= quorumRequired) {
            p.approved = true;
        }

        emit ProposalApproved(id, msg.sender);
    }

    function pauseInfrastructure(uint256 proposalId) external onlyCommittee {
        Proposal storage p = proposals[proposalId];
        require(p.approved, "Proposal not approved");
        pausedTargets[p.target] = true;
        emit InfrastructurePaused(p.target);
    }

    function isPaused(address target) external view returns (bool) {
        return pausedTargets[target];
    }
}
