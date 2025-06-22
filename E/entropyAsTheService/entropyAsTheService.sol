// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title EntropyAsAServiceAttackDefense - Attack and Defense Simulation for Entropy as a Service in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Entropy Service Usage (No verification, Predictable attacks possible)
contract InsecureEntropyService {
    event RandomnessRequested(address indexed user, uint256 entropyUsed);

    function useEntropy(uint256 externalEntropy) external {
        // 🔥 Accepts any random number without validation
        emit RandomnessRequested(msg.sender, externalEntropy);
    }
}

/// @notice Secure Entropy Service Usage with Full VRF-style Verification, Binding, and Replay Protection
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SecureEntropyService is Ownable {
    using ECDSA for bytes32;

    address public trustedEntropySource;
    mapping(bytes32 => bool) public usedEntropySessions;
    uint256 public constant MAX_ENTROPY_AGE = 256; // Blocks

    event VerifiedEntropyUsed(address indexed user, bytes32 entropyHash, bytes32 sessionHash);

    constructor(address _trustedEntropySource) {
        require(_trustedEntropySource != address(0), "Invalid source");
        trustedEntropySource = _trustedEntropySource;
    }

    function useSecureEntropy(
        bytes32 rawEntropy,
        uint256 nonce,
        uint256 providedBlockNumber,
        bytes calldata signature
    ) external {
        require(block.number <= providedBlockNumber + MAX_ENTROPY_AGE, "Entropy expired");

        bytes32 entropyHash = keccak256(abi.encodePacked(rawEntropy, providedBlockNumber, address(this), block.chainid));
        require(!usedEntropySessions[entropyHash], "Entropy already used");

        address signer = entropyHash.toEthSignedMessageHash().recover(signature);
        require(signer == trustedEntropySource, "Invalid entropy signer");

        usedEntropySessions[entropyHash] = true;

        bytes32 sessionHash = keccak256(abi.encodePacked(msg.sender, rawEntropy, nonce, block.number));
        emit VerifiedEntropyUsed(msg.sender, entropyHash, sessionHash);
    }
}

/// @notice Attack contract trying to inject predictable entropy
contract EntropyIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function injectPredictableEntropy(uint256 fakeEntropy) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("useEntropy(uint256)", fakeEntropy)
        );
    }
}
