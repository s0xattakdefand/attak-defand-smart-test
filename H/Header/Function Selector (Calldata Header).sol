contract SelectorInspector {
    function getFunctionSelector(bytes calldata data) external pure returns (bytes4 selector) {
        return bytes4(data[:4]); // First 4 bytes = selector
    }
}
