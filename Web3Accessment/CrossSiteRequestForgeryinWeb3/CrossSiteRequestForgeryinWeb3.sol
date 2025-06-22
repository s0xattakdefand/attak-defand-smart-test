// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title CrossSiteRequestForgeryAttackDefense - Full Attack and Defense Simulation for CSRF in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Secure contract defending against CSRF attempts by using nonce binding
contract SecureCSRFContract {
    address public owner;
    mapping(address => uint256) public nonces;

    event ActionPerformed(address indexed user, uint256 nonce);

    constructor() {
        owner = msg.sender;
    }

    function performAction(uint256 userNonce) external {
        require(userNonce == nonces[msg.sender], "Invalid nonce");
        
        nonces[msg.sender] += 1;
        emit ActionPerformed(msg.sender, userNonce);
    }

    function getCurrentNonce(address user) external view returns (uint256) {
        return nonces[user];
    }
}

/// @notice Attack contract trying to send fake CSRF action with wrong nonce
contract CSRFIntruder {
    address public target;

    constructor(address _target) {
        target = _target;
    }

    // Try to submit an action on behalf of victim without correct nonce
    function tryForgeAction(address victim) external returns (bool success) {
        // Guessing nonce as 0 (wrong guess if user has moved)
        (success, ) = target.call(
            abi.encodeWithSignature("performAction(uint256)", 0)
        );
    }
}
