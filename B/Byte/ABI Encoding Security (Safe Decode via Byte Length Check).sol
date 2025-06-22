contract SafeDecoder {
    function decode(bytes calldata input) public pure returns (uint32) {
        require(input.length == 4, "Expecting 4 bytes only");
        return uint32(bytes4(input)); // ✅ avoids overreads
    }
}
