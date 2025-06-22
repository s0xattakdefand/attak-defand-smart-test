contract DAOBroadcast {
    event ProposalAnnounced(uint256 indexed proposalId, string title, string description, address proposer);

    function announceProposal(uint256 proposalId, string calldata title, string calldata desc) public {
        emit ProposalAnnounced(proposalId, title, desc, msg.sender);
    }
}
