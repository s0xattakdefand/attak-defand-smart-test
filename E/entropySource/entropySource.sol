// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title EntropySourceAttackDefense - Attack and Defense Simulation for Entropy Sources in Solidity Smart Contracts
/// @author ChatGPT

/// @notice Insecure Entropy Source Usage (Weak, Manipulable, Reusable)
contract InsecureEntropySource {
    bytes32 public lastEntropy;

    event EntropyGenerated(bytes32 entropy);

    function generateEntropy() external {
        // 🔥 Weak source: predictable and manipulable by miners
        bytes32 entropy = keccak256(
            abi.encodePacked(block.timestamp, block.coinbase, block.difficulty)
        );
        lastEntropy = entropy;
        emit EntropyGenerated(entropy);
    }
}

/// @notice Secure Entropy Source Usage with Prevrandao + Domain Binding + Freshness Check
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureEntropySource is Ownable {
    bytes32 public lastEntropy;
    uint256 public lastEntropyBlock;
    mapping(bytes32 => bool) public usedEntropies;
    uint256 public constant ENTROPY_VALIDITY = 5 minutes;

    event EntropyGenerated(bytes32 entropy, uint256 blockNumber);

    function generateEntropy() external {
        bytes32 entropy = keccak256(
            abi.encodePacked(
                block.prevrandao,   // unpredictable since London upgrade (EIP-4399)
                block.timestamp,
                block.number,
                msg.sender,
                address(this)
            )
        );
        lastEntropy = entropy;
        lastEntropyBlock = block.timestamp;
        emit EntropyGenerated(entropy, block.number);
    }

    function useEntropy(bytes32 inputEntropy) external returns (bool valid) {
        require(!usedEntropies[inputEntropy], "Entropy already used");
        require(block.timestamp <= lastEntropyBlock + ENTROPY_VALIDITY, "Entropy expired");
        require(inputEntropy == lastEntropy, "Invalid entropy input");

        usedEntropies[inputEntropy] = true;
        return true;
    }
}

/// @notice Intruder trying to predict, drift, or replay entropy
contract EntropySourceIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function predictEntropy() external view returns (bytes32) {
        // Predict insecure entropy
        return keccak256(
            abi.encodePacked(block.timestamp, block.coinbase, block.difficulty)
        );
    }

    function replayEntropy(bytes32 guess) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("useEntropy(bytes32)", guess)
        );
    }
}
