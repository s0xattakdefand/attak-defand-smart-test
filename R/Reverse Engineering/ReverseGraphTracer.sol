contract ReverseGraphTracer {
    event CallTrace(bytes4 selector, bool success);

    function simulate(address target, bytes4[] calldata selectors) external {
        for (uint256 i = 0; i < selectors.length; i++) {
            (bool ok, ) = target.call(abi.encodePacked(selectors[i]));
            emit CallTrace(selectors[i], ok);
        }
    }
}
