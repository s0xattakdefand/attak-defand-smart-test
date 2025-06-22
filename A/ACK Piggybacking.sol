// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PiggybackingVulnerable {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    event Acknowledgment(address indexed user, string message);

    // Vulnerable: ACK piggybacked with administrative action
    function acknowledgeAndAdmin(address user, string calldata message, bool makeOwner) public {
        emit Acknowledgment(user, message);

        // Unauthorized piggybacked operation
        if (makeOwner) {
            owner = user; // Critical unauthorized state change
        }
    }
}
