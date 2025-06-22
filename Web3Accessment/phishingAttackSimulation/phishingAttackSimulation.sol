// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title PhishingAttackDefenseSimulation - Full Attack and Defense Simulation for Phishing Attacks in Web3 Smart Contracts
/// @author ChatGPT

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}

/// @notice Secure Vault with whitelist and explicit user approvals
contract SecureTokenVault {
    address public owner;
    mapping(address => bool) public trustedTokens;
    mapping(address => mapping(address => uint256)) public userTokenAllowances;

    event TokenWhitelisted(address indexed token);
    event AllowanceSet(address indexed user, address indexed token, uint256 amount);
    event TokenTransferred(address indexed user, address indexed token, uint256 amount, address to);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function whitelistToken(address token) external onlyOwner {
        trustedTokens[token] = true;
        emit TokenWhitelisted(token);
    }

    function setAllowance(address token, uint256 amount) external {
        require(trustedTokens[token], "Token not trusted");
        userTokenAllowances[msg.sender][token] = amount;
        emit AllowanceSet(msg.sender, token, amount);
    }

    function transferToken(address token, uint256 amount, address to) external {
        require(trustedTokens[token], "Token not trusted");
        require(userTokenAllowances[msg.sender][token] >= amount, "Allowance exceeded");

        userTokenAllowances[msg.sender][token] -= amount;

        IERC20(token).transferFrom(msg.sender, to, amount);

        emit TokenTransferred(msg.sender, token, amount, to);
    }
}

/// @notice Attack contract simulating phishing for unlimited approvals
contract PhishingAttackSimulator {
    IERC20 public fakeToken;
    address public attacker;

    constructor(address _fakeToken) {
        fakeToken = IERC20(_fakeToken);
        attacker = msg.sender;
    }

    function phishingApproveVictim(address victim) external {
        // Simulate victim signing an unlimited approve (type(uint256).max)
        fakeToken.approve(attacker, type(uint256).max);
    }

    function stealTokens(address victim, uint256 amount) external {
        // Attacker uses stolen approve to move tokens
        fakeToken.transferFrom(victim, attacker, amount);
    }
}
