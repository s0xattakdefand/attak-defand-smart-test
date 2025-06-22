contract UnsafeMemoryWrite {
    function rawWrite(bytes memory input) public pure returns (bytes memory) {
        assembly {
            mstore(add(input, 0x20), 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
        }
        return input;
    }
}
