// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title EntropyAsAServiceAttackDefense - Attack and Defense Simulation for Entropy as a Service in Solidity Smart Contracts
/// @author ChatGPT

/// @notice Insecure Entropy Consumer (No verification, no freshness binding)
contract InsecureEntropyConsumer {
    address public entropyProvider;
    bytes32 public lastEntropy;

    event EntropyRequested(address requester);
    event EntropyReceived(bytes32 entropy);

    constructor(address _entropyProvider) {
        entropyProvider = _entropyProvider;
    }

    function requestEntropy() external {
        emit EntropyRequested(msg.sender);
    }

    function receiveEntropy(bytes32 entropy) external {
        require(msg.sender == entropyProvider, "Invalid provider");
        lastEntropy = entropy;
        emit EntropyReceived(entropy);
    }
}

/// @notice Secure Entropy Consumer with VRF Signature Verification, Freshness Check, and Domain Binding
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SecureEntropyConsumer is Ownable {
    using ECDSA for bytes32;

    address public trustedEntropyProvider;
    bytes32 public lastEntropy;
    uint256 public lastEntropyBlock;
    mapping(bytes32 => bool) public usedEntropies;

    event EntropyRequested(address requester);
    event EntropyReceived(bytes32 entropy, uint256 blockNumber);

    constructor(address _trustedEntropyProvider) {
        trustedEntropyProvider = _trustedEntropyProvider;
    }

    function requestEntropy() external {
        emit EntropyRequested(msg.sender);
    }

    function receiveEntropy(bytes32 entropy, bytes calldata signature) external {
        require(!usedEntropies[entropy], "Entropy already used");

        bytes32 domainBoundEntropy = keccak256(abi.encodePacked(entropy, address(this), block.number));
        address signer = domainBoundEntropy.toEthSignedMessageHash().recover(signature);

        require(signer == trustedEntropyProvider, "Invalid entropy signer");

        lastEntropy = entropy;
        lastEntropyBlock = block.number;
        usedEntropies[entropy] = true;

        emit EntropyReceived(entropy, block.number);
    }
}

/// @notice Intruder trying to replay or fake entropy deliveries
contract EaaSIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function fakeEntropyDelivery(bytes32 fakeEntropy) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("receiveEntropy(bytes32)", fakeEntropy)
        );
    }
}
