// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title EntropyInputAttackDefense - Attack and Defense Simulation for Entropy Inputs in Solidity Smart Contracts
/// @author ChatGPT

/// @notice Insecure Entropy Input Usage (Predictable Source, Reusable, No Context Binding)
contract InsecureEntropyInput {
    bytes32 public lastEntropy;
    uint256 public lastUsedBlock;

    event EntropyGenerated(bytes32 entropy);

    function generateEntropy() external {
        // 🔥 Weak source: block.timestamp is guessable
        bytes32 entropy = keccak256(abi.encodePacked(block.timestamp, block.coinbase));
        lastEntropy = entropy;
        lastUsedBlock = block.number;
        emit EntropyGenerated(entropy);
    }

    function useEntropy(bytes32 inputEntropy) external view returns (bool) {
        return inputEntropy == lastEntropy;
    }
}

/// @notice Secure Entropy Input Usage with Domain Binding, Freshness, and Strong Source
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SecureEntropyInput is Ownable {
    bytes32 public lastEntropy;
    uint256 public lastEntropyBlock;
    mapping(bytes32 => bool) public usedEntropyInputs;

    uint256 public constant ENTROPY_TTL = 5 minutes;

    event EntropyGenerated(bytes32 entropy, uint256 blockNumber);

    function generateEntropy() external {
        bytes32 entropy = keccak256(
            abi.encodePacked(
                block.prevrandao,  // unpredictable source
                block.timestamp,
                msg.sender,
                address(this)
            )
        );

        lastEntropy = entropy;
        lastEntropyBlock = block.timestamp;
        emit EntropyGenerated(entropy, block.number);
    }

    function useEntropy(bytes32 inputEntropy) external returns (bool valid) {
        require(!usedEntropyInputs[inputEntropy], "Entropy already used");
        require(block.timestamp <= lastEntropyBlock + ENTROPY_TTL, "Entropy expired");
        require(inputEntropy == lastEntropy, "Invalid entropy");

        usedEntropyInputs[inputEntropy] = true;
        return true;
    }
}

/// @notice Intruder trying to predict or replay entropy
contract EntropyInputIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function predictEntropy() external view returns (bytes32) {
        return keccak256(abi.encodePacked(block.timestamp, block.coinbase));
    }

    function replayEntropy(bytes32 guess) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("useEntropy(bytes32)", guess)
        );
    }
}
