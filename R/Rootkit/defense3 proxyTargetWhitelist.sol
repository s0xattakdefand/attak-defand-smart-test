contract ProxyAuthWhitelist {
    mapping(address => bool) public approvedTargets;

    function setTarget(address target, bool ok) external {
        approvedTargets[target] = ok;
    }

    function delegate(address to, bytes calldata data) external {
        require(approvedTargets[to], "Unauthorized logic");
        (bool ok, ) = to.delegatecall(data);
        require(ok, "Delegatecall failed");
    }
}
