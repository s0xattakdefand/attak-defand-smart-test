interface ILoopDepthOracle {
    function getDepth(bytes4 selector) external view returns (uint256);
}

contract SimStrategyAI {
    ILoopDepthOracle public loopOracle;
    uint256 public depthLimit = 10;

    constructor(address _oracle) {
        loopOracle = ILoopDepthOracle(_oracle);
    }

    function isSafe(bytes4 sel) public view returns (bool) {
        return loopOracle.getDepth(sel) <= depthLimit;
    }

    function shouldMutate(bytes4 sel) external view returns (bool) {
        uint256 depth = loopOracle.getDepth(sel);
        return depth > 0 && depth <= depthLimit;
    }
}
