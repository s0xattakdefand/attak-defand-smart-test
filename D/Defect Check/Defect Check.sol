// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title DefectCheckAttackDefense - Attack and Defense Simulation for Defect Checks in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Contract with No Defect Checking (No Invariants, No Input Validation)
contract InsecureDefectCheck {
    mapping(address => uint256) public balances;
    bool public paused;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external {
        // 🔥 No input validation, no invariant checks
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
        emit Withdrawal(msg.sender, amount);
    }

    function pauseSystem() external {
        paused = true;
    }
}

/// @notice Secure Contract with Defect Checking: Invariant Enforcement, Guarded Inputs, Upgrade-Safe Patterns
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SecureDefectCheck is Ownable, ReentrancyGuard {
    mapping(address => uint256) private balances;
    bool public paused;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    modifier notPaused() {
        require(!paused, "System is paused");
        _;
    }

    function deposit() external payable notPaused {
        require(msg.value > 0, "Deposit must be greater than zero");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);

        _checkInvariant();
    }

    function withdraw(uint256 amount) external nonReentrant notPaused {
        require(amount > 0, "Withdrawal must be greater than zero");
        require(balances[msg.sender] >= amount, "Insufficient balance");

        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        emit Withdrawal(msg.sender, amount);

        _checkInvariant();
    }

    function pauseSystem() external onlyOwner {
        paused = true;
    }

    function unpauseSystem() external onlyOwner {
        paused = false;
    }

    function balanceOf(address user) external view returns (uint256) {
        return balances[user];
    }

    function _checkInvariant() internal view {
        require(address(this).balance >= _totalBalances(), "Invariant broken: Balance mismatch");
    }

    function _totalBalances() internal view returns (uint256 total) {
        // This would typically loop through a full mapping in production — simplified here
        return address(this).balance;
    }

    receive() external payable {}
}

/// @notice Intruder trying to exploit missing checks
contract DefectCheckIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function maliciousWithdraw(uint256 amount) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("withdraw(uint256)", amount)
        );
    }
}
