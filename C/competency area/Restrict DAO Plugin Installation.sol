interface ICompetencyAreaRegistry {
    function hasMinimumLevel(address, string calldata, uint) external view returns (bool);
}

contract DAOPluginInstaller {
    ICompetencyAreaRegistry public registry;
    string constant AREA = "Governance";

    constructor(address registryAddr) {
        registry = ICompetencyAreaRegistry(registryAddr);
    }

    function install(bytes calldata pluginData) external {
        require(registry.hasMinimumLevel(msg.sender, AREA, uint(CompetencyAreaRegistry.Level.Maintainer)), "Insufficient level");
        // Proceed with plugin registration
    }
}
