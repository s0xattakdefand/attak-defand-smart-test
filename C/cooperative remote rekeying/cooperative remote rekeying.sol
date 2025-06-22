// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CooperativeRemoteRekeying {
    address public admin;
    uint256 public threshold;
    uint256 public proposalNonce;

    struct RekeyProposal {
        bytes newKey;
        uint256 approvals;
        bool executed;
        mapping(address => bool) approvedBy;
    }

    mapping(uint256 => RekeyProposal) public proposals;
    mapping(address => bool) public participants;
    uint256 public participantCount;

    event ParticipantAdded(address participant);
    event RekeyProposalCreated(uint256 nonce, bytes newKey);
    event RekeyApproved(uint256 nonce, address approver, uint256 approvalCount);
    event RekeyExecuted(uint256 nonce, bytes newKey);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin allowed");
        _;
    }

    modifier onlyParticipant() {
        require(participants[msg.sender], "Only participants allowed");
        _;
    }

    constructor(uint256 _threshold) {
        require(_threshold > 0, "Invalid threshold");
        admin = msg.sender;
        threshold = _threshold;
        proposalNonce = 1;
    }

    // Admin adds participants
    function addParticipant(address _participant) external onlyAdmin {
        require(!participants[_participant], "Already a participant");
        participants[_participant] = true;
        participantCount++;
        emit ParticipantAdded(_participant);
    }

    // Admin creates rekey proposal
    function proposeRekey(bytes memory _newKey) external onlyAdmin {
        RekeyProposal storage proposal = proposals[proposalNonce];
        proposal.newKey = _newKey;
        proposal.approvals = 0;
        proposal.executed = false;

        emit RekeyProposalCreated(proposalNonce, _newKey);
        proposalNonce++;
    }

    // Participants approve proposal
    function approveRekey(uint256 _nonce) external onlyParticipant {
        RekeyProposal storage proposal = proposals[_nonce];
        require(proposal.newKey.length != 0, "Proposal doesn't exist");
        require(!proposal.executed, "Already executed");
        require(!proposal.approvedBy[msg.sender], "Already approved");

        proposal.approvedBy[msg.sender] = true;
        proposal.approvals++;

        emit RekeyApproved(_nonce, msg.sender, proposal.approvals);

        if (proposal.approvals >= threshold) {
            executeRekey(_nonce);
        }
    }

    // Internal execution upon reaching threshold
    function executeRekey(uint256 _nonce) internal {
        RekeyProposal storage proposal = proposals[_nonce];
        require(!proposal.executed, "Already executed");
        require(proposal.approvals >= threshold, "Insufficient approvals");

        proposal.executed = true;

        // Here, implement logic to utilize the newKey as needed (e.g., updating a public key reference)
        emit RekeyExecuted(_nonce, proposal.newKey);
    }

    // View proposal approvals
    function getApprovals(uint256 _nonce) external view returns (uint256) {
        return proposals[_nonce].approvals;
    }
}
