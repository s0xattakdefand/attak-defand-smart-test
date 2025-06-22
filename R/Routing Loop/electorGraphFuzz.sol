contract SelectorGraphFuzz {
    event Fuzz(bytes4 selector, bool recursed);

    function fuzz(address target, bytes4[] calldata selectors, uint8 maxDepth) external {
        for (uint i = 0; i < selectors.length; i++) {
            _fuzzSelector(target, selectors[i], maxDepth);
        }
    }

    function _fuzzSelector(address target, bytes4 sel, uint8 depth) internal {
        if (depth == 0) return;
        (bool ok, ) = target.call(abi.encodePacked(sel));
        emit Fuzz(sel, ok);
        if (ok) _fuzzSelector(target, sel, depth - 1); // detect potential recursion
    }
}
