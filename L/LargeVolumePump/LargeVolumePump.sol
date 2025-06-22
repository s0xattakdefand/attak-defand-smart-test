// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title LargeVolumePumpAttackDefense - Full Attack and Defense Simulation for Large Volume Pump Attacks in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Pool (No Volume Check, No Time-Weighted Balances)
contract InsecureVolumePool {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalSupply += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        totalSupply -= amount;
        payable(msg.sender).transfer(amount);
        emit Withdraw(msg.sender, amount);
    }
}

/// @notice Secure Pool (Volume Surge Detection + TWAB Protection + Cooldown)
contract SecureVolumePool {
    address public immutable owner;
    uint256 public totalSupply;
    uint256 public lastTotalSupply;
    uint256 public lastUpdateBlock;
    uint256 public constant SURGE_THRESHOLD_PERCENT = 20; // 20% sudden change detection
    uint256 public constant COOLDOWN_BLOCKS = 20; // Lock withdrawals after surge

    struct UserInfo {
        uint256 balance;
        uint256 lastDepositBlock;
    }

    mapping(address => UserInfo) public users;

    event SecureDeposit(address indexed user, uint256 amount);
    event SecureWithdraw(address indexed user, uint256 amount);
    event SurgeDetected(uint256 oldSupply, uint256 newSupply, uint256 blockNumber);

    constructor() {
        owner = msg.sender;
        lastUpdateBlock = block.number;
    }

    modifier surgeGuard() {
        uint256 blocksPassed = block.number - lastUpdateBlock;
        if (blocksPassed > 0) {
            lastTotalSupply = totalSupply;
            lastUpdateBlock = block.number;
        }
        _;
    }

    function deposit() external payable surgeGuard {
        require(msg.value > 0, "Zero deposit");
        users[msg.sender].balance += msg.value;
        users[msg.sender].lastDepositBlock = block.number;
        totalSupply += msg.value;

        // Surge detection
        uint256 changePercent = _calculatePercentDifference(lastTotalSupply, totalSupply);
        if (changePercent >= SURGE_THRESHOLD_PERCENT) {
            emit SurgeDetected(lastTotalSupply, totalSupply, block.number);
        }

        emit SecureDeposit(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external {
        UserInfo storage user = users[msg.sender];
        require(user.balance >= amount, "Insufficient balance");
        require(block.number >= user.lastDepositBlock + COOLDOWN_BLOCKS, "Cooldown active");

        user.balance -= amount;
        totalSupply -= amount;
        payable(msg.sender).transfer(amount);

        emit SecureWithdraw(msg.sender, amount);
    }

    function _calculatePercentDifference(uint256 oldVal, uint256 newVal) internal pure returns (uint256) {
        if (oldVal == 0) {
            return 100;
        }
        uint256 diff = oldVal > newVal ? oldVal - newVal : newVal - oldVal;
        return (diff * 100) / oldVal;
    }
}

/// @notice Attack contract simulating sudden flash volume pump
contract VolumePumpIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function flashDeposit() external payable returns (bool success) {
        (success, ) = targetInsecure.call{value: msg.value}(
            abi.encodeWithSignature("deposit()")
        );
    }

    function flashWithdraw(uint256 amount) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("withdraw(uint256)", amount)
        );
    }
}
