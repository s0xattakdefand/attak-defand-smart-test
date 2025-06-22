contract RPCSelectorScanner {
    event Probe(bytes4 selector, bool success);
    event FailedReplay(bytes4 selector, address target);

    function probe(address target, bytes4[] calldata selectors) external {
        for (uint i = 0; i < selectors.length; i++) {
            (bool ok, ) = target.staticcall(abi.encodePacked(selectors[i]));
            emit Probe(selectors[i], ok);
            if (!ok) emit FailedReplay(selectors[i], target);
        }
    }
}
