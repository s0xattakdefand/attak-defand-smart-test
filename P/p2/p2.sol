// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title P2ParameterAttackDefense - Attack and Defense Simulation for Second Parameter (P2) Handling in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure P2 Handling (No Validation, Vulnerable to Mode Injection)
contract InsecureP2 {
    event ActionExecuted(address indexed caller, uint8 p2, string action);

    function executeAction(uint8 p2, string calldata action) external {
        // 🔥 No validation on P2 parameter!
        emit ActionExecuted(msg.sender, p2, action);
    }
}

/// @notice Secure P2 Handling with Full Validation and Replay Protection
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SecureP2 is Ownable {
    using ECDSA for bytes32;

    mapping(bytes32 => bool) public usedActions;
    uint8 public constant MIN_P2 = 0;
    uint8 public constant MAX_P2 = 5;

    event ActionExecuted(address indexed caller, uint8 p2, string action, bytes32 actionHash);

    function executeSecureAction(uint8 p2, string calldata action, uint256 nonce, bytes calldata signature) external {
        require(p2 >= MIN_P2 && p2 <= MAX_P2, "P2 out of bounds");

        bytes32 actionHash = keccak256(abi.encodePacked(msg.sender, p2, action, nonce, address(this), block.chainid));
        require(!usedActions[actionHash], "Replay detected");

        address signer = actionHash.toEthSignedMessageHash().recover(signature);
        require(signer == msg.sender, "Invalid signature");

        usedActions[actionHash] = true;
        emit ActionExecuted(msg.sender, p2, action, actionHash);
    }
}

/// @notice Attack contract trying to forge P2 for unauthorized actions
contract P2Intruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function injectForgedP2(uint8 forgedP2, string calldata action) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("executeAction(uint8,string)", forgedP2, action)
        );
    }
}
