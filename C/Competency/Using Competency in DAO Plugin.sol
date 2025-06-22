interface ICompetencyRegistry {
    function hasLevel(address actor, string calldata domain, uint requiredLevel) external view returns (bool);
}

contract SecureProposal {
    ICompetencyRegistry public registry;
    string constant DOMAIN = "DAOProposal";

    constructor(address registryAddr) {
        registry = ICompetencyRegistry(registryAddr);
    }

    function submitProposal(string calldata text) external {
        require(registry.hasLevel(msg.sender, DOMAIN, uint(CompetencyRegistry.Level.Verified)), "Insufficient competency");
        // Accept proposal...
    }
}
