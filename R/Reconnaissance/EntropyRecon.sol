contract EntropyRecon {
    event Drift(bytes4 selector, uint8 entropy);

    function driftScore(bytes4 sel) public pure returns (uint8 score) {
        uint32 x = uint32(sel);
        while (x > 0) {
            score++;
            x &= (x - 1);
        }
    }

    function logEntropy(bytes4 sel) external {
        emit Drift(sel, driftScore(sel));
    }
}
