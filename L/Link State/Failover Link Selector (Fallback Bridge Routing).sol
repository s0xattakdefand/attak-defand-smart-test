pragma solidity ^0.8.21;

interface IBridge {
    function send(address to, uint256 amount) external;
}

contract LinkStateFailover {
    address public primaryBridge;
    address public fallbackBridge;
    LinkStateRegistry public registry;

    constructor(address _reg, address _primary, address _fallback) {
        registry = LinkStateRegistry(_reg);
        primaryBridge = _primary;
        fallbackBridge = _fallback;
    }

    function routeFunds(address to, uint256 amount) external {
        if (registry.isActive(primaryBridge)) {
            IBridge(primaryBridge).send(to, amount);
        } else {
            require(registry.isActive(fallbackBridge), "No working links");
            IBridge(fallbackBridge).send(to, amount);
        }
    }
}
