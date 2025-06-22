// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title EVMAttackDefense - Full Attack and Defense Simulation for Common EVM-Level Vulnerabilities in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Contract Vulnerable to EVM-Level Attacks
contract InsecureEVMContract {
    address public owner;
    address public target;

    constructor(address _target) {
        owner = msg.sender;
        target = _target;
    }

    function unsafeDelegatecall(bytes calldata data) external {
        (bool success, ) = target.delegatecall(data);
        require(success, "Delegatecall failed");
    }

    function kill() external {
        require(msg.sender == owner, "Only owner");
        selfdestruct(payable(owner));
    }

    function externalCall(address payable to, uint256 amount) external {
        require(msg.sender == owner, "Only owner");
        (bool success, ) = to.call{value: amount}("");
        require(success, "Call failed"); // But does not check gas used
    }

    receive() external payable {}
}

/// @notice Secure EVM Contract (Full EVM Hardening)
contract SecureEVMContract {
    address public owner;
    bool private locked;

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    modifier lock() {
        require(!locked, "Reentrancy Guard");
        locked = true;
        _;
        locked = false;
    }

    constructor() {
        owner = msg.sender;
    }

    function safeExternalCall(address payable to, uint256 amount) external onlyOwner lock {
        require(address(this).balance >= amount, "Insufficient balance");

        (bool success, ) = to.call{value: amount, gas: 2300}(""); // Limit gas sent
        require(success, "External call failed");
    }

    function protectedDelegatecall(address target, bytes calldata data) external onlyOwner lock {
        require(target != address(0), "Invalid target");
        require(isContract(target), "Target not a contract");

        (bool success, ) = target.delegatecall(data);
        require(success, "Safe delegatecall failed");
    }

    function isContract(address account) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(account) }
        return size > 0;
    }

    function destroyContract() external onlyOwner {
        // Remove dangerous selfdestruct logic - owner must explicitly drain funds
        revert("Selfdestruct disabled");
    }

    receive() external payable {}
}

/// @notice Attack contract trying to exploit unsafe EVM operations
contract EVMIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function hijackDelegatecall(bytes calldata maliciousData) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("unsafeDelegatecall(bytes)", maliciousData)
        );
    }

    function killContract() external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("kill()")
        );
    }
}
