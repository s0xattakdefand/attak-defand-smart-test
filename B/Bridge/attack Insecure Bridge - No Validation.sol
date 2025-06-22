// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract InsecureBridge {
    event Bridged(address indexed user, uint256 amount, string destinationChain);

    function bridgeOut(uint256 amount, string calldata destinationChain) public {
        // ❌ No lock, no burn, no proof. Anyone can emit fake bridge intent.
        emit Bridged(msg.sender, amount, destinationChain);
    }
}
