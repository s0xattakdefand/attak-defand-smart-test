interface ILoopRouterA {
    function bounceBack(uint256 value) external;
}

contract LoopRouterB {
    address public routerA;

    constructor(address _a) {
        routerA = _a;
    }

    function bounceBack(uint256 value) external {
        if (value > 0) {
            ILoopRouterA(routerA).bounceBack(value - 1);
        }
    }
}
