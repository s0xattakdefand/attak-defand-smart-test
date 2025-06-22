interface IRiskRegistry {
    function score(bytes4 sel) external view returns (uint256);
}

contract SimStrategyAI {
    IRiskRegistry public risk;

    constructor(address _risk) {
        risk = IRiskRegistry(_risk);
    }

    function pick(bytes4[] calldata selectors) external view returns (bytes4 best) {
        uint256 top = 0;
        for (uint i = 0; i < selectors.length; i++) {
            uint256 s = risk.score(selectors[i]);
            if (s > top) {
                best = selectors[i];
                top = s;
            }
        }
    }
}
