// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract WormBomb {
    event SpamLog(uint256 indexed id, string message);

    // Infinite loop event spam to fill logs
    function grief(uint256 loops) external {
        for (uint256 i = 0; i < loops; i++) {
            emit SpamLog(i, "🔥 Worm log spam");
        }
    }

    // Infinite fallback loop
    fallback() external payable {
        while (true) {
            emit SpamLog(block.number, "🌀 Looping fallback...");
        }
    }

    receive() external payable {}
}
