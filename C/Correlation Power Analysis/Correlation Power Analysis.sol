// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CPAMitigation {
    mapping(address => uint256) private secrets;

    event Processed(address indexed user, uint256 masked);

    constructor() {
        // Simulate secret initialization
        secrets[msg.sender] = uint256(keccak256(abi.encodePacked(block.timestamp)));
    }

    /// ❌ Vulnerable to CPA: gas varies based on secret
    function leakViaGas(uint256 guess) external view returns (bool) {
        uint256 secret = secrets[msg.sender];
        if (guess == secret) {
            return true; // Short path
        } else {
            // Longer branch
            for (uint256 i = 0; i < 10; i++) {
                guess = uint256(keccak256(abi.encodePacked(guess, i)));
            }
            return false;
        }
    }

    /// ✅ Constant-time simulated defense
    function hardenedCompare(uint256 guess) external returns (bool) {
        uint256 secret = secrets[msg.sender];

        // Simulate constant path length
        uint256 dummy = 0;
        bool matchFlag = false;

        for (uint256 i = 0; i < 10; i++) {
            uint256 a = uint256(keccak256(abi.encodePacked(guess, i)));
            uint256 b = uint256(keccak256(abi.encodePacked(secret, i)));
            dummy ^= a ^ b;
        }

        if (guess == secret) {
            matchFlag = true;
        }

        // Emit dummy to equalize gas
        emit Processed(msg.sender, dummy);

        return matchFlag;
    }
}
