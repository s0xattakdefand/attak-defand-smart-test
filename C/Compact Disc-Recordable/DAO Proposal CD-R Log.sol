contract ProposalLog {
    CDRRegistry public registry;
    uint256 public nextId;

    constructor(address _registry) {
        registry = CDRRegistry(_registry);
    }

    function submitProposal(string calldata metadataURI, bytes32 hash) external {
        registry.burnCD(nextId++, "DAO Proposal", metadataURI, hash);
    }
}
