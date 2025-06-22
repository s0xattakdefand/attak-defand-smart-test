// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract NFT {
    string public name = "ActiveNFT";
    string public symbol = "ANFT";
    uint256 public totalSupply;

    mapping(address => uint256) public balances;

    function mint(uint256 amount) external {
        totalSupply += amount;
        balances[msg.sender] += amount;
    }

    function balanceOf(address user) external view returns (uint256) {
        return balances[user];
    }
}
