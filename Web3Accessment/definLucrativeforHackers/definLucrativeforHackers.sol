// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title DeFiLucrativeHackersAttackDefense - Full Attack and Defense Simulation for DeFi Systems Exploited by Hackers in Web3 Smart Contracts
/// @author ChatGPT

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @notice Secure DeFi Vault with multiple defense layers
contract SecureDeFiVault {
    address public asset;
    address public owner;
    uint256 public reserve;
    uint256 public lastSnapshotBlock;
    bool private locked;
    uint256 public flashloanCooldown = 5 blocks;
    uint256 public upgradeDelay = 2 days;
    address public pendingUpgrade;
    uint256 public upgradeReadyTime;

    modifier lock() {
        require(!locked, "Reentrancy Guard");
        locked = true;
        _;
        locked = false;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    constructor(address _asset) {
        owner = msg.sender;
        asset = _asset;
        lastSnapshotBlock = block.number;
    }

    function deposit(uint256 amount) external lock {
        require(amount > 0, "Invalid deposit");
        IERC20(asset).transferFrom(msg.sender, address(this), amount);
        reserve += amount;
        takeSnapshot();
    }

    function withdraw(uint256 amount) external lock {
        require(amount <= reserve, "Insufficient liquidity");
        IERC20(asset).transfer(msg.sender, amount);
        reserve -= amount;
        takeSnapshot();
    }

    function swap(uint256 amountIn, uint256 minOut, uint256 currentOraclePrice) external lock returns (uint256 amountOut) {
        uint256 estimatedOut = (amountIn * currentOraclePrice) / 1e18;
        require(estimatedOut >= minOut, "Slippage limit exceeded");

        IERC20(asset).transferFrom(msg.sender, address(this), amountIn);
        IERC20(asset).transfer(msg.sender, estimatedOut);

        reserve = reserve + amountIn - estimatedOut;
        takeSnapshot();
        return estimatedOut;
    }

    function guardedBorrow(uint256 amount) external lock {
        require(amount <= reserve / 2, "Over-borrow risk");
        require(block.number > lastSnapshotBlock + flashloanCooldown, "Flashloan cooldown active");

        IERC20(asset).transfer(msg.sender, amount);
        reserve -= amount;
        takeSnapshot();
    }

    function proposeUpgrade(address newImplementation) external onlyOwner {
        pendingUpgrade = newImplementation;
        upgradeReadyTime = block.timestamp + upgradeDelay;
    }

    function executeUpgrade() external onlyOwner {
        require(block.timestamp >= upgradeReadyTime, "Upgrade delay not passed");
        // Simulation: In real upgradeable proxies, this would set a new logic address.
        pendingUpgrade = address(0);
    }

    function takeSnapshot() internal {
        lastSnapshotBlock = block.number;
    }

    function getReserve() external view returns (uint256) {
        return reserve;
    }
}

/// @notice Attack contract simulating flashloan and phishing exploits
contract DeFiHackersIntruder {
    address public targetVault;
    address public token;

    constructor(address _targetVault, address _token) {
        targetVault = _targetVault;
        token = _token;
    }

    function flashLoanAttack(uint256 amount) external {
        IERC20(token).transferFrom(msg.sender, address(this), amount);

        (bool success, ) = targetVault.call(
            abi.encodeWithSignature("guardedBorrow(uint256)", amount)
        );
        require(success, "Borrow failed");

        IERC20(token).transferFrom(address(this), msg.sender, amount);
    }
}
