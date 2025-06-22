// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ParsecAttackDefense - Attack and Defense Simulation for Long-Distance (Parsec) Operations in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Long-Range Message Execution (No Freshness or State Validation)
contract InsecureParsec {
    mapping(bytes32 => bool) public processedRequests;

    event MessageProcessed(address indexed sender, uint256 value, uint256 timestamp);

    function submitMessage(uint256 value, uint256 timestamp) external {
        // 🔥 No freshness or replay check
        emit MessageProcessed(msg.sender, value, timestamp);
    }
}

/// @notice Secure Long-Range Message Execution (Freshness, Replay Guard, State Verification)
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureParsec is Ownable {
    mapping(bytes32 => bool) public processedRequests;
    uint256 public constant MAX_DELAY = 5 minutes;

    event MessageProcessed(address indexed sender, uint256 value, uint256 timestamp, bytes32 requestId);

    function submitMessage(uint256 value, uint256 timestamp, bytes32 requestId) external {
        require(!processedRequests[requestId], "Request already processed");
        require(block.timestamp - timestamp <= MAX_DELAY, "Message too old");

        processedRequests[requestId] = true;

        emit MessageProcessed(msg.sender, value, timestamp, requestId);
    }
}

/// @notice Attack contract simulating replay and stale message injection
contract ParsecIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function submitOldMessage(uint256 value, uint256 fakeTimestamp) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("submitMessage(uint256,uint256)", value, fakeTimestamp)
        );
    }
}
