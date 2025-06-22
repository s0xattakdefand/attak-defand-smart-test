// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title WebSecurityTestingAttackDefense - Full Simulation of Web3 Security Testing on Smart Contracts
/// @author ChatGPT

/// @notice Secure smart contract defending against web security attacks
contract SecureWebContract {
    address public owner;
    mapping(address => bool) private admins;
    uint256 private totalSupply;
    uint256 public depositLimit = 100 ether;

    event Deposited(address indexed user, uint256 amount);
    event EmergencyHalt();

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyAdmin() {
        require(admins[msg.sender], "Not admin");
        _;
    }

    modifier validateDeposit(uint256 amount) {
        require(amount > 0 && amount <= depositLimit, "Invalid deposit amount");
        _;
    }

    constructor() {
        owner = msg.sender;
        admins[msg.sender] = true;
    }

    function addAdmin(address _admin) external onlyOwner {
        admins[_admin] = true;
    }

    function removeAdmin(address _admin) external onlyOwner {
        admins[_admin] = false;
    }

    function deposit() external payable validateDeposit(msg.value) {
        totalSupply += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function emergencyHalt() external onlyAdmin {
        emit EmergencyHalt();
    }

    fallback() external payable {
        revert("Fallback not allowed");
    }

    receive() external payable {
        revert("Direct ETH not accepted");
    }

    function getTotalSupply() external view returns (uint256) {
        return totalSupply;
    }
}

/// @notice Attack contract trying to bypass protections
contract WebSecurityIntruder {
    address public target;

    constructor(address _target) {
        target = _target;
    }

    // Try to call emergency halt without being admin
    function tryEmergencyHalt() external returns (bool success) {
        (success, ) = target.call(
            abi.encodeWithSignature("emergencyHalt()")
        );
    }

    // Try to exploit fallback
    function tryFallbackExploit() external payable returns (bool success) {
        (success, ) = target.call{value: msg.value}(abi.encodePacked(uint256(123456)));
    }

    // Try to overflow deposit
    function tryOverDeposit() external payable returns (bool success) {
        (success, ) = target.call{value: 200 ether}(
            abi.encodeWithSignature("deposit()")
        );
    }
}
