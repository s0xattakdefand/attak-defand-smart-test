// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CSSPABCouncil {
    address public admin;
    mapping(address => bool) public boardMembers;
    mapping(bytes32 => bool) public approvedAuditHashes;
    mapping(uint256 => bool) public vetoedProposals;

    uint256 public constant MIN_APPROVALS = 3;
    mapping(uint256 => uint256) public proposalApprovals;

    event BoardMemberAdded(address indexed member);
    event BoardMemberRemoved(address indexed member);
    event ProposalApproved(uint256 indexed id, address approver);
    event ProposalVetoed(uint256 indexed id, address vetoer);
    event AuditApproved(bytes32 indexed auditHash);

    modifier onlyBoard() {
        require(boardMembers[msg.sender], "Not a board member");
        _;
    }

    constructor() {
        admin = msg.sender;
        boardMembers[admin] = true;
    }

    function addBoardMember(address member) external {
        require(msg.sender == admin, "Not admin");
        boardMembers[member] = true;
        emit BoardMemberAdded(member);
    }

    function removeBoardMember(address member) external {
        require(msg.sender == admin, "Not admin");
        boardMembers[member] = false;
        emit BoardMemberRemoved(member);
    }

    function approveProposal(uint256 proposalId) external onlyBoard {
        proposalApprovals[proposalId]++;
        emit ProposalApproved(proposalId, msg.sender);
    }

    function vetoProposal(uint256 proposalId) external onlyBoard {
        vetoedProposals[proposalId] = true;
        emit ProposalVetoed(proposalId, msg.sender);
    }

    function isProposalApproved(uint256 proposalId) external view returns (bool) {
        return proposalApprovals[proposalId] >= MIN_APPROVALS && !vetoedProposals[proposalId];
    }

    function approveAudit(bytes32 auditHash) external onlyBoard {
        approvedAuditHashes[auditHash] = true;
        emit AuditApproved(auditHash);
    }

    function isAuditApproved(bytes32 auditHash) external view returns (bool) {
        return approvedAuditHashes[auditHash];
    }
}
