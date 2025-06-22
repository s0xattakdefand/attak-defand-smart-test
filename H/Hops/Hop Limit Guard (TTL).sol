contract HopLimitRouter {
    uint256 public constant MAX_HOPS = 3;

    struct Route {
        address[] targets;
        bytes[] payloads;
    }

    event HopExecuted(address target);

    function route(Route calldata r) external {
        require(r.targets.length <= MAX_HOPS, "Too many hops");
        for (uint256 i = 0; i < r.targets.length; i++) {
            (bool ok, ) = r.targets[i].call(r.payloads[i]);
            require(ok, "Hop failed");
            emit HopExecuted(r.targets[i]);
        }
    }
}
