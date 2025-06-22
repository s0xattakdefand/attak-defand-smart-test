// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract FullDuplexSwap {
    function atomicSwap(
        address tokenA,
        address userA,
        uint256 amountA,
        address tokenB,
        address userB,
        uint256 amountB
    ) external {
        require(
            IERC20(tokenA).transferFrom(userA, userB, amountA) &&
            IERC20(tokenB).transferFrom(userB, userA, amountB),
            "Swap failed"
        );
    }
}
