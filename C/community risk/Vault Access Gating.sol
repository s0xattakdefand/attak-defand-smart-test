interface IRiskRegistry {
    function getRisk(address actor) external view returns (CommunityRiskRegistry.ActorRisk memory);
}

contract RiskAwareVault {
    IRiskRegistry public riskRegistry;

    constructor(address registryAddr) {
        riskRegistry = IRiskRegistry(registryAddr);
    }

    function withdraw(uint256 amount) external {
        require(riskRegistry.getRisk(msg.sender).riskScore <= 50, "High risk actor");
        // Proceed with withdrawal
    }
}
