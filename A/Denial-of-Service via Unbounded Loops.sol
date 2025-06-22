// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DoS_UnboundedLoop {
    address[] public users;

    function register() public {
        users.push(msg.sender);
    }

    // ❌ DoS: This loop can run out of gas if users list grows large
    function rewardAll() public {
        for (uint256 i = 0; i < users.length; i++) {
            payable(users[i]).transfer(1 ether); // may cause OOG
        }
    }

    receive() external payable {}
}
