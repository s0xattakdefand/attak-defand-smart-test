contract RouteSigVerifier {
    mapping(bytes4 => address) public expectedTargets;

    function setExpected(bytes4 selector, address target) external {
        expectedTargets[selector] = target;
    }

    function isValidRoute(bytes4 selector, address actual) external view returns (bool) {
        return expectedTargets[selector] == actual;
    }
}
