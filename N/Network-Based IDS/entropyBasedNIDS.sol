contract NIDSEntropyDetector {
    mapping(bytes4 => uint256) public selectorEntropy;
    mapping(bytes4 => uint256) public lastObserved;

    event EntropyAlert(address indexed from, bytes4 selector, uint256 drift);

    function log(bytes4 selector) external {
        uint256 nowTime = block.number;
        if (lastObserved[selector] != 0) {
            uint256 drift = nowTime - lastObserved[selector];
            if (drift > 1000) { // Long-lost selector = possible replay
                emit EntropyAlert(msg.sender, selector, drift);
            }
        }
        lastObserved[selector] = nowTime;
        selectorEntropy[selector]++;
    }
}
