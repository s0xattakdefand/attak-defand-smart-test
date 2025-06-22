interface IRIPRouterRegistry {
    function getRoute(address from, bytes4 selector) external view returns (address target, uint8 hopCount);
}

contract RIPRouter {
    IRIPRouterRegistry public registry;

    constructor(address _registry) {
        registry = IRIPRouterRegistry(_registry);
    }

    event RoutedCall(address indexed to, bytes4 selector, uint8 hops);

    function forward(bytes calldata callData) external {
        bytes4 selector = bytes4(callData);
        (address next, uint8 hops) = registry.getRoute(msg.sender, selector);
        require(next != address(0), "No route");
        emit RoutedCall(next, selector, hops);
        (bool ok, ) = next.call(callData);
        require(ok, "RIP route failed");
    }
}
