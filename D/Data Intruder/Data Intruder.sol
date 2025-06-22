// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title DataIntruderAttackDefense - Full Attack and Defense Simulation for Data Intruders
/// @author ChatGPT

/// @notice Secure contract protecting sensitive data
contract SecureDataStorage {
    address public owner;
    mapping(address => uint256) private userBalances;
    mapping(address => bool) private admins;

    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);
    event AdminAdded(address indexed newAdmin);
    event AdminRemoved(address indexed removedAdmin);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyAdmin() {
        require(admins[msg.sender], "Not admin");
        _;
    }

    constructor() {
        owner = msg.sender;
        admins[msg.sender] = true; // Owner is also an admin
    }

    function addAdmin(address _admin) external onlyOwner {
        admins[_admin] = true;
        emit AdminAdded(_admin);
    }

    function removeAdmin(address _admin) external onlyOwner {
        admins[_admin] = false;
        emit AdminRemoved(_admin);
    }

    function deposit() external payable {
        require(msg.value > 0, "No value sent");
        userBalances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 _amount) external {
        require(userBalances[msg.sender] >= _amount, "Insufficient balance");
        userBalances[msg.sender] -= _amount;
        payable(msg.sender).transfer(_amount);
        emit Withdraw(msg.sender, _amount);
    }

    function getBalance(address _user) external view onlyAdmin returns (uint256) {
        return userBalances[_user];
    }
}

/// @notice Attack contract attempting to intrude into SecureDataStorage
contract Intruder {
    address public target;

    constructor(address _target) {
        target = _target;
    }

    // Attempt to access internal/private data by force
    function sneakPeek(address victim) external returns (uint256 victimBalance) {
        // Tries to call getBalance without admin rights
        (bool success, bytes memory data) = target.call(
            abi.encodeWithSignature("getBalance(address)", victim)
        );

        require(success, "Call failed");

        // Try to decode balance if possible
        victimBalance = abi.decode(data, (uint256));
    }
}
