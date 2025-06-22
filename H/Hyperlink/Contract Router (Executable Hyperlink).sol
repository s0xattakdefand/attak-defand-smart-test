contract HyperRouter {
    mapping(string => address) public destinations;

    function register(string calldata path, address contractAddr) external {
        destinations[path] = contractAddr;
    }

    function callPath(string calldata path, bytes calldata data) external {
        address target = destinations[path];
        require(target != address(0), "No route");
        (bool ok, ) = target.call(data);
        require(ok, "Call failed");
    }
}
