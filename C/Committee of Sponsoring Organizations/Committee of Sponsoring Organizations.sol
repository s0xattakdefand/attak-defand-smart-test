// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract COSOGovernanceController {
    address public admin;
    mapping(address => bool) public approvers;
    uint256 public approvalThreshold;

    struct ActionProposal {
        address proposer;
        string description;
        uint256 approvals;
        bool executed;
        mapping(address => bool) approvedBy;
    }

    uint256 public proposalCount;
    mapping(uint256 => ActionProposal) private proposals;

    event ApproverAdded(address approver);
    event ProposalCreated(uint256 indexed id, string description);
    event ProposalApproved(uint256 indexed id, address indexed approver, uint256 approvals);
    event ProposalExecuted(uint256 indexed id);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier onlyApprover() {
        require(approvers[msg.sender], "Not an approver");
        _;
    }

    constructor(address[] memory initialApprovers, uint256 threshold) {
        require(threshold > 0, "Invalid threshold");
        admin = msg.sender;
        approvalThreshold = threshold;

        for (uint256 i = 0; i < initialApprovers.length; i++) {
            approvers[initialApprovers[i]] = true;
            emit ApproverAdded(initialApprovers[i]);
        }
    }

    function createProposal(string calldata description) external onlyApprover returns (uint256) {
        uint256 id = proposalCount++;
        ActionProposal storage p = proposals[id];
        p.proposer = msg.sender;
        p.description = description;

        emit ProposalCreated(id, description);
        return id;
    }

    function approveProposal(uint256 id) external onlyApprover {
        ActionProposal storage p = proposals[id];
        require(!p.executed, "Already executed");
        require(!p.approvedBy[msg.sender], "Already approved");

        p.approvedBy[msg.sender] = true;
        p.approvals++;

        emit ProposalApproved(id, msg.sender, p.approvals);

        if (p.approvals >= approvalThreshold) {
            executeProposal(id);
        }
    }

    function executeProposal(uint256 id) internal {
        ActionProposal storage p = proposals[id];
        require(!p.executed, "Already executed");
        require(p.approvals >= approvalThreshold, "Not enough approvals");

        p.executed = true;
        emit ProposalExecuted(id);

        // Real action logic would go here (e.g., upgrade, fund transfer, DAO vote)
    }

    // View function for external auditors or DAOs
    function getProposal(uint256 id) external view returns (
        address proposer, string memory description, uint256 approvals, bool executed
    ) {
        ActionProposal storage p = proposals[id];
        return (p.proposer, p.description, p.approvals, p.executed);
    }
}
