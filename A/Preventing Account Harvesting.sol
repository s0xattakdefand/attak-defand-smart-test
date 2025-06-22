// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SecureAccountManagement {
    mapping(address => uint256) private balances;
    mapping(address => bool) private registered;

    event UserRegistered(address indexed user);

    modifier onlyRegistered() {
        require(registered[msg.sender], "Not registered");
        _;
    }

    function registerUser() public {
        require(!registered[msg.sender], "Already registered");
        registered[msg.sender] = true;
        balances[msg.sender] = 1 ether;

        emit UserRegistered(msg.sender);
    }

    // Secure: Users can only access their own data
    function getMyBalance() public view onlyRegistered returns (uint256) {
        return balances[msg.sender];
    }

    // Optional: Admin-controlled enumeration with strict authorization
    address private owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Unauthorized");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // Admin-only enumeration, not publicly accessible
    address[] private userAccounts;

    function adminGetAllUsers() public view onlyOwner returns (address[] memory) {
        return userAccounts;
    }

    // Securely track user accounts internally (hidden from public)
    function registerUserSecure() public {
        require(!registered[msg.sender], "Already registered");
        registered[msg.sender] = true;
        balances[msg.sender] = 1 ether;
        userAccounts.push(msg.sender);

        emit UserRegistered(msg.sender);
    }
}
