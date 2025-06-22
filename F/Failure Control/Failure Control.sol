// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title FailureControlAttackDefense - Full Attack and Defense Simulation for Failure Control Vulnerabilities in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Failure Control Manager (Vulnerable to Partial Execution and Silent Failures)
contract InsecureFailureControl {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(address payable to, uint256 amount) external {
        if (balances[msg.sender] >= amount) {
            (bool sent, ) = to.call{value: amount}("");
            // BAD: No check if call failed!
            balances[msg.sender] -= amount;
        }
    }

    receive() external payable {}
}

/// @notice Secure Failure Control Manager (Full Atomic and Verified Failure Control)
contract SecureFailureControl {
    mapping(address => uint256) public balances;
    bool private locked;

    event WithdrawalFailed(address indexed to, uint256 amount, string reason);

    modifier noReentrancy() {
        require(!locked, "Reentrancy Guard");
        locked = true;
        _;
        locked = false;
    }

    constructor() {}

    function deposit() external payable noReentrancy {
        balances[msg.sender] += msg.value;
    }

    function safeWithdraw(address payable to, uint256 amount) external noReentrancy {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        balances[msg.sender] -= amount; // Update state BEFORE external call (checks-effects-interactions)

        (bool sent, ) = to.call{value: amount}("");
        if (!sent) {
            balances[msg.sender] += amount; // Rollback if transfer fails
            emit WithdrawalFailed(to, amount, "Transfer failed");
            revert("Withdrawal failed");
        }
    }

    function getBalance(address user) external view returns (uint256) {
        return balances[user];
    }

    receive() external payable {}
}

/// @notice Attack contract simulating silent failure exploits
contract FailureControlIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function abuseSilentFailure(uint256 amount) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("withdraw(address,uint256)", address(this), amount)
        );
    }
}
