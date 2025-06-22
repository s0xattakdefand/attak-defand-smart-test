interface IFunctionScanner {
    function bruteSelectors(address target) external view returns (bytes4[] memory);
}

contract AutoSimExecutor {
    IFunctionScanner public scanner;
    IPayloadRepo public repo;

    constructor(address _scanner, address _repo) {
        scanner = IFunctionScanner(_scanner);
        repo = IPayloadRepo(_repo);
    }

    function discoverAndRun(address target) external {
        bytes4[] memory selectors = scanner.bruteSelectors(target);
        for (uint256 i = 0; i < selectors.length; i++) {
            bytes memory payload = abi.encodePacked(selectors[i]);
            (bool ok, ) = target.call(payload);
            emit SimResult(target, selectors[i], ok);
        }
    }

    event SimResult(address indexed target, bytes4 selector, bool success);
}
