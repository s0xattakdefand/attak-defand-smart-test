// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title SecureStorageAttackDefense - Full Attack and Defense Simulation for Secure Storage Practices in Web3 Contracts
/// @author ChatGPT

/// @notice Secure smart contract implementing proper storage security
contract SecureStorageContract {
    address public immutable deployer; // Immutable storage for deployer
    address private admin; // Private storage to hide admin

    mapping(address => uint256) private balances; // Sensitive balance mapping
    uint256 private totalSupply;

    uint256[50] private __gap; // Storage gap for upgradeable compatibility

    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    constructor() {
        deployer = msg.sender;
        admin = msg.sender;
    }

    function deposit() external payable {
        require(msg.value > 0, "No value sent");
        balances[msg.sender] += msg.value;
        totalSupply += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 _amount) external {
        require(balances[msg.sender] >= _amount, "Insufficient balance");
        balances[msg.sender] -= _amount;
        totalSupply -= _amount;
        payable(msg.sender).transfer(_amount);
        emit Withdraw(msg.sender, _amount);
    }

    function changeAdmin(address newAdmin) external onlyAdmin {
        require(newAdmin != address(0), "Invalid address");
        admin = newAdmin;
    }

    function getBalance(address _user) external view returns (uint256) {
        return balances[_user];
    }

    function getTotalSupply() external view returns (uint256) {
        return totalSupply;
    }
}

/// @notice Attack contract trying to overwrite or read storage improperly
contract StorageIntruder {
    address public target;

    constructor(address _target) {
        target = _target;
    }

    // Try to manipulate storage by calling admin functions
    function tryChangeAdmin(address newAdmin) external returns (bool success) {
        (success, ) = target.call(
            abi.encodeWithSignature("changeAdmin(address)", newAdmin)
        );
    }

    // Try to probe public getters for sensitive storage
    function tryGetBalance(address victim) external view returns (uint256 balance) {
        (bool success, bytes memory data) = target.staticcall(
            abi.encodeWithSignature("getBalance(address)", victim)
        );
        require(success, "Read failed");
        balance = abi.decode(data, (uint256));
    }
}
