contract SelectorEntropyMonitor {
    mapping(bytes4 => uint256) public hits;
    event Radiation(bytes4 selector, uint8 entropy);

    function logSelector(bytes4 sel) public {
        hits[sel]++;
        emit Radiation(sel, entropy(sel));
    }

    function entropy(bytes4 sel) public pure returns (uint8 score) {
        uint32 x = uint32(sel);
        while (x != 0) {
            score++;
            x &= x - 1;
        }
    }
}
