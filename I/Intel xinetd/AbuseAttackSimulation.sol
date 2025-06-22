contract FuzzRouterAbuse {
    function spamFallback(address target) external {
        for (uint i = 0; i < 10; i++) {
            (bool ok, ) = target.call(abi.encodeWithSelector(bytes4(keccak256("junk()"))));
            require(ok, "Call failed");
        }
    }
}
