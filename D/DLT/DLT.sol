// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Decentralized Liquidity Token (DLT) smart contract
contract DLT {
    // Token details
    string public constant name = "Decentralized Liquidity Token";
    string public constant symbol = "DLT";
    uint8 public constant decimals = 18;
    
    // Total supply of DLT tokens
    uint256 public totalSupply;
    
    // Balances of DLT tokens
    mapping(address => uint256) public balanceOf;
    
    // Total liquidity in the pool (in wei)
    uint256 public totalLiquidity;
    
    // Owner of the contract
    address public owner;
    
    // Accumulated fees (in wei)
    uint256 public collectedFees;
    
    // Event emitted when tokens are minted
    event Mint(address indexed user, uint256 tokens, uint256 ethAmount);
    
    // Event emitted when tokens are burned
    event Burn(address indexed user, uint256 tokens, uint256 ethAmount);
    
    // Event emitted when fees are collected
    event FeesCollected(uint256 amount);
    
    // Modifier to restrict actions to the owner
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }
    
    // Constructor to initialize the owner
    constructor() {
        owner = msg.sender;
        totalSupply = 0;
        totalLiquidity = 0;
        collectedFees = 0;
    }
    
    // Deposit ETH to receive DLT tokens
    function deposit() external payable returns (uint256) {
        require(msg.value > 0, "Must send ETH to deposit");
        
        uint256 tokensToMint;
        if (totalLiquidity == 0 || totalSupply == 0) {
            // Initial deposit: 1 ETH = 1000 DLT tokens (arbitrary ratio)
            tokensToMint = msg.value * 1000;
        } else {
            // Proportional minting based on existing liquidity
            tokensToMint = (msg.value * totalSupply) / totalLiquidity;
        }
        
        require(tokensToMint > 0, "Insufficient tokens to mint");
        
        totalLiquidity += msg.value;
        totalSupply += tokensToMint;
        balanceOf[msg.sender] += tokensToMint;
        
        emit Mint(msg.sender, tokensToMint, msg.value);
        return tokensToMint;
    }
    
    // Withdraw ETH by burning DLT tokens
    function withdraw(uint256 tokenAmount) external {
        require(tokenAmount > 0, "Must specify tokens to burn");
        require(balanceOf[msg.sender] >= tokenAmount, "Insufficient token balance");
        require(totalSupply > 0, "No tokens in circulation");
        
        // Calculate proportional ETH to withdraw
        uint256 ethToWithdraw = (tokenAmount * totalLiquidity) / totalSupply;
        require(ethToWithdraw <= totalLiquidity, "Insufficient liquidity");
        
        totalLiquidity -= ethToWithdraw;
        totalSupply -= tokenAmount;
        balanceOf[msg.sender] -= tokenAmount;
        
        // Transfer ETH to user
        payable(msg.sender).transfer(ethToWithdraw);
        
        emit Burn(msg.sender, tokenAmount, ethToWithdraw);
    }
    
    // Collect fees (e.g., from external transactions, simulated here)
    function collectFees() external payable {
        require(msg.value > 0, "No fees sent");
        collectedFees += msg.value;
        totalLiquidity += msg.value;
        
        emit FeesCollected(msg.value);
    }
    
    // Distribute collected fees to liquidity providers
    function distributeFees() external onlyOwner {
        require(collectedFees > 0, "No fees to distribute");
        require(totalSupply > 0, "No tokens in circulation");
        
        // Fees are absorbed into totalLiquidity, so no additional action needed
        // Liquidity providers benefit proportionally on withdrawal
        collectedFees = 0;
    }
    
    // Get user's share of the pool
    function getUserShare(address user) external view returns (uint256) {
        if (totalSupply == 0) return 0;
        return (balanceOf[user] * totalLiquidity) / totalSupply;
    }
    
    // Emergency withdraw by owner (in case funds are stuck)
    function emergencyWithdraw() external onlyOwner {
        uint256 amount = address(this).balance;
        require(amount > 0, "No funds to withdraw");
        payable(owner).transfer(amount);
        totalLiquidity = 0;
        collectedFees = 0;
    }
    
    // Receive function to accept ETH for fees or deposits
    receive() external payable {
        // Treat direct ETH transfers as fee contributions
        if (msg.value > 0) {
            collectedFees += msg.value;
            totalLiquidity += msg.value;
            emit FeesCollected(msg.value);
        }
    }
}