interface IRiskAverseGuard {
    function selectorEntropy(bytes4 sel) external view returns (uint8);
}

contract SimStrategyAI {
    IRiskAverseGuard public guard;

    constructor(address _guard) {
        guard = IRiskAverseGuard(_guard);
    }

    function recommend(bytes4[] calldata selectors) external view returns (bytes4 best) {
        uint8 max = 0;
        for (uint i = 0; i < selectors.length; i++) {
            uint8 e = guard.selectorEntropy(selectors[i]);
            if (e > max) {
                best = selectors[i];
                max = e;
            }
        }
    }
}
