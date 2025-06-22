// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title PassiveAttackDefense - Attack and Defense Simulation for Passive Attack Scenarios in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Contract Exposing Critical Metadata
contract InsecurePassiveTarget {
    uint256 public publicState;
    uint256 public secretNumber;

    event StateChanged(uint256 newValue);
    event SecretCalculated(uint256 secret);

    constructor() {
        publicState = 42;
        secretNumber = uint256(keccak256(abi.encodePacked(block.timestamp, blockhash(block.number - 1))));
    }

    function updateState(uint256 newValue) external {
        publicState = newValue;
        emit StateChanged(newValue);
    }

    function leakSecret() external view returns (uint256) {
        // 🔥 Secret value easily viewable!
        return secretNumber;
    }
}

/// @notice Secure Contract Obfuscating and Hiding Critical Metadata
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecurePassiveTarget is Ownable {
    bytes32 private commitHash;
    uint256 private revealBlock;
    bool public committed;

    event CommitSubmitted(address indexed committer, uint256 blockNumber);
    event RevealAccepted(address indexed revealer, uint256 value);

    function commitSecret(bytes32 _commitHash) external onlyOwner {
        commitHash = _commitHash;
        revealBlock = block.number + 5; // Commit phase enforced
        committed = true;
        emit CommitSubmitted(msg.sender, block.number);
    }

    function revealSecret(uint256 secretValue, uint256 salt) external onlyOwner {
        require(committed, "No active commit");
        require(block.number >= revealBlock, "Reveal not allowed yet");
        require(keccak256(abi.encodePacked(secretValue, salt)) == commitHash, "Invalid reveal");

        committed = false;
        emit RevealAccepted(msg.sender, secretValue);
    }
}

/// @notice Passive attack simulation contract trying to observe secrets
contract PassiveIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function observeSecret() external view returns (uint256 secret) {
        (, bytes memory data) = targetInsecure.staticcall(
            abi.encodeWithSignature("leakSecret()")
        );
        secret = abi.decode(data, (uint256));
    }
}
