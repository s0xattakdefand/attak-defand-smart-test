contract UnsafeDecode {
    function decode(bytes calldata input) external pure returns (uint256) {
        // ❌ Can panic if input < 32 bytes
        (uint256 x) = abi.decode(input, (uint256));
        return x;
    }
}
