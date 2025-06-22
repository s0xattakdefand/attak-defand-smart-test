contract ABIMappingScanner {
    function scan(address target, bytes4[] calldata selectors) external view returns (bool[] memory results) {
        results = new bool[](selectors.length);
        for (uint256 i = 0; i < selectors.length; i++) {
            (bool ok, ) = target.staticcall(abi.encodePacked(selectors[i]));
            results[i] = ok;
        }
    }
}
