// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IRouterB {
    function forwardFromA(uint256 value) external;
}

contract RouterA {
    address public b;

    constructor(address _b) {
        b = _b;
    }

    function forwardFromB(uint256 value) external {
        require(value > 0, "Invalid");
        IRouterB(b).forwardFromA(value - 1);
    }
}
