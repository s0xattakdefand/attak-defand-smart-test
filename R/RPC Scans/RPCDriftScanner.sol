contract RPCDriftScanner {
    mapping(bytes4 => uint8) public entropy;

    event DriftDetected(bytes4 selector, uint8 bits);

    function fuzz(bytes4 selector) public {
        uint8 bits = countBits(selector);
        entropy[selector] = bits;
        emit DriftDetected(selector, bits);
    }

    function countBits(bytes4 sel) internal pure returns (uint8 b) {
        uint32 x = uint32(sel);
        while (x != 0) { b++; x &= (x - 1); }
    }
}
