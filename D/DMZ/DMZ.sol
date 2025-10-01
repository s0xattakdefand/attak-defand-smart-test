// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title DMZ
 * @dev A simple ERC20 token contract named "DMZ".
 * This is a sample implementation assuming the query refers to a token smart contract.
 * If this is not what you meant, please provide more details!
 */
contract DMZ is ERC20, Ownable {
    constructor(address initialOwner)
        ERC20("DMZ", "DMZ")
        Ownable(initialOwner)
    {
        _mint(msg.sender, 1000000 * 10 ** decimals()); // Mint 1 million tokens to deployer
    }

    /**
     * @dev Mint additional tokens (only owner).
     */
    function mint(address to, uint256 amount) public onlyOwner {
        _mint(to, amount);
    }
}