contract EntropyDefenseAI {
    uint8 public maxEntropy = 6;

    function check(bytes4 sel) public view returns (bool) {
        return selectorEntropy(sel) <= maxEntropy;
    }

    function selectorEntropy(bytes4 sel) public pure returns (uint8 e) {
        uint32 x = uint32(sel);
        while (x != 0) { e++; x &= (x - 1); }
    }

    function adjust(uint8 newEntropyLimit) external {
        maxEntropy = newEntropyLimit;
    }
}
