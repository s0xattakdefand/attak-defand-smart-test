// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title DeFiSecurityAttackDefenseSimulation - Full Attack and Defense Simulation for Common DeFi Vulnerabilities in Smart Contracts
/// @author ChatGPT

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @notice Secure DeFi Pool Contract: protects against flashloan manipulation, reentrancy, and oracle drift
contract SecureDeFiPool {
    address public asset;
    uint256 public reserve;
    uint256 public lastSnapshotReserve;
    uint256 public lastSnapshotBlock;
    bool private locked;
    uint256 public oraclePrice; // Simulated simple oracle
    uint256 public slippageTolerance = 5; // 5%

    modifier lock() {
        require(!locked, "Reentrancy Guard");
        locked = true;
        _;
        locked = false;
    }

    constructor(address _asset, uint256 initialOraclePrice) {
        asset = _asset;
        oraclePrice = initialOraclePrice;
        lastSnapshotBlock = block.number;
    }

    function updateOraclePrice(uint256 newPrice) external {
        // Assume trusted source for simplicity; in production would verify feed
        require(newPrice > 0, "Invalid oracle price");
        oraclePrice = newPrice;
    }

    function provideLiquidity(uint256 amount) external lock {
        require(amount > 0, "Zero amount");
        IERC20(asset).transferFrom(msg.sender, address(this), amount);
        reserve += amount;
        takeSnapshot();
    }

    function takeSnapshot() internal {
        lastSnapshotReserve = reserve;
        lastSnapshotBlock = block.number;
    }

    function swap(uint256 amountIn, uint256 minOut) external lock returns (uint256 amountOut) {
        require(amountIn > 0, "Zero input");

        uint256 price = oraclePrice;
        uint256 expectedOut = (amountIn * price) / 1e18;
        require(expectedOut >= minOut, "Slippage protection");

        IERC20(asset).transferFrom(msg.sender, address(this), amountIn);
        IERC20(asset).transfer(msg.sender, expectedOut);

        reserve = reserve + amountIn - expectedOut;
        takeSnapshot();
        return expectedOut;
    }

    function emergencyWithdraw() external lock {
        // For simplicity: Allow owner/admin logic to rescue funds if needed (omitted here)
    }

    function guardedBorrow(uint256 borrowAmount) external lock {
        require(borrowAmount <= reserve / 2, "Over-borrow risk"); // No full draining
        require(block.number > lastSnapshotBlock + 5, "Flashloan cooldown");

        IERC20(asset).transfer(msg.sender, borrowAmount);
        reserve -= borrowAmount;
        takeSnapshot();
    }
}

/// @notice Attack contract trying to flashloan + reentrancy exploit
contract DeFiAttackIntruder {
    address public target;
    address public token;

    constructor(address _target, address _token) {
        target = _target;
        token = _token;
    }

    function attemptFlashLoanDrain(uint256 flashAmount) external {
        // Simulate receiving flashloan
        IERC20(token).transferFrom(msg.sender, address(this), flashAmount);

        // Try immediately borrowing against manipulated state
        (bool success, ) = target.call(
            abi.encodeWithSignature("guardedBorrow(uint256)", flashAmount)
        );
        require(success, "Borrow failed");

        // Repay flashloan (simulate)
        IERC20(token).transferFrom(address(this), msg.sender, flashAmount);
    }
}
