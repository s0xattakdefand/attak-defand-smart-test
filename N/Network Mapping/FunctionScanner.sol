contract FunctionScanner {
    function bruteSelectors(address target) external view returns (bytes4[] memory live) {
        bytes4 ;
        uint256 count = 0;

        for (uint256 i = 0; i < 256; i++) {
            bytes4 sel = bytes4(uint32(i << 24));
            (bool ok, ) = target.staticcall(abi.encodePacked(sel));
            if (ok) {
                results[count++] = sel;
            }
        }

        assembly { mstore(results, count) }
        return results;
    }
}
