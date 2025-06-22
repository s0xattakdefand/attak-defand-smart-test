interface IEntropyTracker {
    function selectorEntropy(bytes4 sel) external view returns (uint8);
}

contract ABIMutator {
    ILoopDepthOracle public loop;
    IEntropyTracker public entropy;

    struct Score {
        bytes4 selector;
        uint256 score;
    }

    function scoreSelector(bytes4 sel) public view returns (uint256) {
        uint8 e = entropy.selectorEntropy(sel);
        uint256 d = loop.getDepth(sel);
        return uint256(e) * (d + 1); // weighted score
    }

    function mutate(bytes4[] memory selList) public view returns (bytes4 best) {
        uint256 top;
        for (uint i = 0; i < selList.length; i++) {
            uint256 s = scoreSelector(selList[i]);
            if (s > top) {
                top = s;
                best = selList[i];
            }
        }
    }
}
