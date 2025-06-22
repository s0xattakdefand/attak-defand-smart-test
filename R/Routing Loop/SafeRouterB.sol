interface ISafeRouterA {
    function bounceBack(uint256 value) external;
}

contract SafeRouterB is LoopGuard {
    address public routerA;

    constructor(address _a, address _uplink) LoopGuard(_uplink) {
        routerA = _a;
    }

    function bounceBack(uint256 value) external guardLoop(10) {
        if (value > 0) {
            ISafeRouterA(routerA).bounceBack(value - 1);
        }
    }
}
