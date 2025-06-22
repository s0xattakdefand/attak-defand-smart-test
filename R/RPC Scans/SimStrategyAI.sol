interface IRPCDriftScanner {
    function entropy(bytes4 sel) external view returns (uint8);
}

contract SimStrategyAI {
    IRPCDriftScanner public drift;

    constructor(address _drift) {
        drift = IRPCDriftScanner(_drift);
    }

    function rankByEntropy(bytes4[] calldata selectors) external view returns (bytes4 best) {
        uint8 max = 0;
        for (uint i = 0; i < selectors.length; i++) {
            uint8 score = drift.entropy(selectors[i]);
            if (score > max) {
                max = score;
                best = selectors[i];
            }
        }
    }
}
