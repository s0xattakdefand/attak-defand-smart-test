// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title WalletSecurityPhishingAttackDefense - Attack and Defense Simulation for Wallet Security and Phishing Prevention in Web3 Smart Contracts
/// @author ChatGPT

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @notice Secure vault that restricts approvals and contract interactions
contract SecureWalletVault {
    address public owner;
    mapping(address => bool) public trustedContracts;
    mapping(address => uint256) public approvedLimits;

    event ContractWhitelisted(address indexed contractAddress);
    event TokenApproved(address indexed token, uint256 limit);
    event TokensTransferred(address indexed token, address indexed to, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function whitelistContract(address _contract) external onlyOwner {
        require(_contract != address(0), "Invalid contract");
        trustedContracts[_contract] = true;
        emit ContractWhitelisted(_contract);
    }

    function approveToken(address token, uint256 limit) external onlyOwner {
        require(token != address(0), "Invalid token");
        require(limit > 0, "Limit must be > 0");
        approvedLimits[token] = limit;
        emit TokenApproved(token, limit);
    }

    function safeTransfer(address token, address to, uint256 amount) external {
        require(trustedContracts[msg.sender], "Caller not trusted");
        require(amount <= approvedLimits[token], "Amount exceeds approved limit");

        IERC20(token).transferFrom(owner, to, amount);
        approvedLimits[token] -= amount;

        emit TokensTransferred(token, to, amount);
    }
}

/// @notice Attack contract trying to exploit wallet security flaws
contract WalletPhishingIntruder {
    address public target;

    constructor(address _target) {
        target = _target;
    }

    function tryStealTokens(address token, address victim, uint256 amount) external returns (bool success) {
        (success, ) = target.call(
            abi.encodeWithSignature(
                "safeTransfer(address,address,uint256)",
                token,
                victim,
                amount
            )
        );
    }
}
