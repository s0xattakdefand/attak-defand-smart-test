// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title DefectTypeAttackDefense - Attack and Defense Simulation for Defect Types in Solidity Smart Contracts
/// @author ChatGPT

/// @notice Insecure Contract with Multiple Defect Types
contract InsecureDefectType {
    mapping(address => uint256) public balances;
    address public owner;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
    event OwnershipTransferred(address indexed newOwner);

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Not enough balance");
        (bool success, ) = msg.sender.call{value: amount}(""); // 🔥 Unsafe external call
        require(success, "Withdraw failed");

        balances[msg.sender] -= amount;
        emit Withdrawal(msg.sender, amount);
    }

    function transferOwnership(address newOwner) external {
        // 🔥 No onlyOwner protection
        owner = newOwner;
        emit OwnershipTransferred(newOwner);
    }

    function unsafeAdd(uint256 a, uint256 b) external pure returns (uint256) {
        return a + b; // 🔥 No overflow protection
    }

    receive() external payable {}
}

/// @notice Secure Contract with Protection Against Each Defect Type
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SecureDefectType is Ownable, ReentrancyGuard {
    mapping(address => uint256) private balances;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    function deposit() external payable {
        require(msg.value > 0, "Zero deposit not allowed");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Withdrawal failed");

        emit Withdrawal(msg.sender, amount);
    }

    function safeAdd(uint256 a, uint256 b) external pure returns (uint256) {
        unchecked {
            uint256 c = a + b;
            require(c >= a, "Overflow occurred");
            return c;
        }
    }

    function balanceOf(address user) external view returns (uint256) {
        return balances[user];
    }

    receive() external payable {}
}

/// @notice Intruder contract trying to exploit different defect types
contract DefectTypeIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function stealOwnership(address attacker) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("transferOwnership(address)", attacker)
        );
    }

    function overflowBalance(uint256 hugeAmount) external pure returns (uint256 result) {
        return hugeAmount + hugeAmount;
    }

    function reentrancyAttack(uint256 amount) external payable returns (bool success) {
        (success, ) = targetInsecure.call{value: msg.value}(abi.encodeWithSignature("deposit()"));
        require(success, "Deposit failed");

        (success, ) = targetInsecure.call(abi.encodeWithSignature("withdraw(uint256)", amount));
    }

    receive() external payable {}
}
