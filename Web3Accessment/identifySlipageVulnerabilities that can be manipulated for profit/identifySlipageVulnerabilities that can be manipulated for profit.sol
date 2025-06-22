// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title SlippageAttackDefenseSimulation - Full Attack and Defense Simulation for Slippage Vulnerabilities in Web3 Smart Contracts
/// @author ChatGPT

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @notice Secure Swap contract enforcing slippage protections
contract SecureSwapPool {
    address public tokenX;
    address public tokenY;
    uint256 public reserveX;
    uint256 public reserveY;

    bool private locked;

    modifier lock() {
        require(!locked, "Reentrancy Guard");
        locked = true;
        _;
        locked = false;
    }

    constructor(address _tokenX, address _tokenY) {
        tokenX = _tokenX;
        tokenY = _tokenY;
    }

    function provideLiquidity(uint256 amountX, uint256 amountY) external lock {
        require(amountX > 0 && amountY > 0, "Zero liquidity not allowed");

        IERC20(tokenX).transferFrom(msg.sender, address(this), amountX);
        IERC20(tokenY).transferFrom(msg.sender, address(this), amountY);

        reserveX += amountX;
        reserveY += amountY;
    }

    function swap(address fromToken, uint256 amountIn, uint256 minOut) external lock returns (uint256 amountOut) {
        require(fromToken == tokenX || fromToken == tokenY, "Invalid token");

        if (fromToken == tokenX) {
            require(reserveX > 0 && reserveY > 0, "Empty pool");
            uint256 k = reserveX * reserveY;
            uint256 newReserveX = reserveX + amountIn;
            uint256 newReserveY = k / newReserveX;
            amountOut = reserveY - newReserveY;

            require(amountOut >= minOut, "Slippage tolerance exceeded");

            IERC20(tokenX).transferFrom(msg.sender, address(this), amountIn);
            IERC20(tokenY).transfer(msg.sender, amountOut);

            reserveX = newReserveX;
            reserveY = newReserveY;
        } else {
            require(reserveX > 0 && reserveY > 0, "Empty pool");
            uint256 k = reserveX * reserveY;
            uint256 newReserveY = reserveY + amountIn;
            uint256 newReserveX = k / newReserveY;
            amountOut = reserveX - newReserveX;

            require(amountOut >= minOut, "Slippage tolerance exceeded");

            IERC20(tokenY).transferFrom(msg.sender, address(this), amountIn);
            IERC20(tokenX).transfer(msg.sender, amountOut);

            reserveX = newReserveX;
            reserveY = newReserveY;
        }
    }

    function getReserves() external view returns (uint256, uint256) {
        return (reserveX, reserveY);
    }
}

/// @notice Attack contract simulating slippage exploitation attempt
contract SlippageAttackIntruder {
    address public targetPool;
    address public tokenX;
    address public tokenY;

    constructor(address _targetPool, address _tokenX, address _tokenY) {
        targetPool = _targetPool;
        tokenX = _tokenX;
        tokenY = _tokenY;
    }

    function simulateSlippageDrain(address fromToken, uint256 amountIn) external {
        IERC20(fromToken).transferFrom(msg.sender, address(this), amountIn);
        IERC20(fromToken).approve(targetPool, amountIn);

        // Call swap without worrying about output (unsafe)
        (bool success, ) = targetPool.call(
            abi.encodeWithSignature("swap(address,uint256,uint256)", fromToken, amountIn, 0)
        );
        require(success, "Swap failed");
    }
}
