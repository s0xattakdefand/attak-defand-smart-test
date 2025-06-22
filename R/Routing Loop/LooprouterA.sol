// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface ILoopRouterB {
    function bounceBack(uint256 value) external;
}

contract LoopRouterA {
    address public routerB;

    constructor(address _b) {
        routerB = _b;
    }

    function triggerLoop(uint256 value) external {
        require(value > 0, "Invalid input");
        ILoopRouterB(routerB).bounceBack(value - 1);
    }

    function bounceBack(uint256 value) external {
        if (value > 0) {
            ILoopRouterB(routerB).bounceBack(value - 1);
        }
    }
}
