// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title P1ParameterAttackDefense - Attack and Defense Simulation for First Parameter (p1) Handling in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure p1 Handling (No Validation, Vulnerable to Drift and Replay)
contract InsecureP1 {
    event CommandExecuted(address indexed caller, uint8 p1, string action);

    function executeCommand(uint8 p1, string calldata action) external {
        // 🔥 No validation of p1 values!
        emit CommandExecuted(msg.sender, p1, action);
    }
}

/// @notice Secure p1 Handling with Full Validation and Replay Protection
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SecureP1 is Ownable {
    using ECDSA for bytes32;

    mapping(bytes32 => bool) public usedCommands;
    uint8 public constant MIN_P1 = 1;
    uint8 public constant MAX_P1 = 10;

    event CommandExecuted(address indexed caller, uint8 p1, string action, bytes32 commandHash);

    function executeSecureCommand(uint8 p1, string calldata action, uint256 nonce, bytes calldata signature) external {
        require(p1 >= MIN_P1 && p1 <= MAX_P1, "p1 out of bounds");

        bytes32 commandHash = keccak256(abi.encodePacked(msg.sender, p1, action, nonce, address(this), block.chainid));
        require(!usedCommands[commandHash], "Replay detected");

        address signer = commandHash.toEthSignedMessageHash().recover(signature);
        require(signer == msg.sender, "Invalid signature");

        usedCommands[commandHash] = true;
        emit CommandExecuted(msg.sender, p1, action, commandHash);
    }
}

/// @notice Attack contract simulating malicious p1 injection and replay
contract P1Intruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function injectMaliciousP1(uint8 forgedP1, string calldata action) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("executeCommand(uint8,string)", forgedP1, action)
        );
    }
}
