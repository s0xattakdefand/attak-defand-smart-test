interface ITierRegistry {
    function userTier(address) external view returns (uint8);
}

contract TreasuryModule {
    ITierRegistry public tierRegistry;

    constructor(address registry) {
        tierRegistry = ITierRegistry(registry);
    }

    modifier onlyTier1() {
        require(tierRegistry.userTier(msg.sender) == 1, "T1 only");
        _;
    }

    function withdrawEmergency(address to, uint256 amount) external onlyTier1 {
        // emergency vault access
    }
}
