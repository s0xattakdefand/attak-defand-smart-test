contract FakeRouteInjector {
    IRIPRouterRegistry public registry;

    constructor(address _reg) {
        registry = IRIPRouterRegistry(_reg);
    }

    function inject(bytes4 selector, address to) external {
        // Claim route with low hop to trick router
        registry.registerRoute(selector, to, 1);
    }
}
