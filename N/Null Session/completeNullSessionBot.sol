// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract NullSessionBot {
    using ECDSA for bytes32;

    address public owner;
    mapping(address => uint256) public failedCalls;
    mapping(address => bool) public blacklisted;
    uint256 public failThreshold = 3;

    event NullAttempt(address indexed target, bytes4 selector, bool success);
    event Blocked(address indexed target);

    constructor() {
        owner = msg.sender;
    }

    // 👾 Attempt null session calls to targets
    function probeFallback(address target, uint256 attempts) external {
        require(msg.sender == owner, "Only owner");
        for (uint256 i = 0; i < attempts; i++) {
            bytes4 sel = bytes4(keccak256(abi.encodePacked(block.timestamp, target, i)));
            (bool ok, ) = target.call(abi.encodePacked(sel));
            emit NullAttempt(target, sel, ok);

            if (!ok) {
                failedCalls[target]++;
                if (failedCalls[target] >= failThreshold && !blacklisted[target]) {
                    blacklisted[target] = true;
                    emit Blocked(target);
                }
            }
        }
    }

    // 🛡️ Defensive simulation: block known unauth selectors
    fallback() external {
        require(!blacklisted[msg.sender], "You are blocked due to null session abuse");
        // normal fallback logic (optional)
    }

    function setThreshold(uint256 newThreshold) external {
        require(msg.sender == owner, "Only owner");
        failThreshold = newThreshold;
    }
}
