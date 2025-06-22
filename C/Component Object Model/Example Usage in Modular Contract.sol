interface IStrategy {
    function execute(uint256 amount) external;
}

contract Vault {
    ComInterfaceRegistry public registry;
    bytes4 public constant STRATEGY_INTERFACE = type(IStrategy).interfaceId;

    constructor(address registryAddr) {
        registry = ComInterfaceRegistry(registryAddr);
    }

    function callStrategy(uint256 amount) external {
        address strat = registry.resolve(STRATEGY_INTERFACE);
        IStrategy(strat).execute(amount);
    }
}
