// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title DN
 * @dev A simple ERC20 token contract named "DN".
 * This implementation assumes the query refers to a token smart contract.
 * If this is not what you meant, please provide more details!
 */
contract DN is ERC20, Ownable {
    constructor(address initialOwner)
        ERC20("DN", "DN")
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