// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title QuasiCyclicSyndromeDecodingAttackDefense - Attack and Defense Simulation for Quasi-Cyclic Syndrome Decoding in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Syndrome Decoding (No Session Binding, No Validation)
contract InsecureSyndromeDecoding {
    mapping(address => bytes32) public submittedSyndromes;

    event SyndromeSubmitted(address indexed user, bytes32 syndrome);

    function submitSyndrome(bytes32 syndrome) external {
        // 🔥 Accept any syndrome without context, no validation
        submittedSyndromes[msg.sender] = syndrome;
        emit SyndromeSubmitted(msg.sender, syndrome);
    }
}

/// @notice Secure Syndrome Decoding Handling with Full Validation, Session Binding, and Replay Protection
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SecureSyndromeDecoding is Ownable {
    using ECDSA for bytes32;

    mapping(bytes32 => bool) public usedSyndromes;
    uint256 public constant REQUIRED_SYNDROME_WEIGHT = 20; // Expected number of 1 bits for a valid syndrome

    event SyndromeAccepted(address indexed user, bytes32 syndrome, bytes32 sessionHash);

    function submitSecureSyndrome(
        bytes32 syndrome,
        uint256 nonce,
        bytes calldata signature
    ) external {
        require(validateSyndromeWeight(syndrome), "Invalid syndrome weight");

        bytes32 sessionHash = keccak256(abi.encodePacked(msg.sender, syndrome, nonce, address(this), block.chainid));
        require(!usedSyndromes[sessionHash], "Syndrome already used");

        address signer = sessionHash.toEthSignedMessageHash().recover(signature);
        require(signer == msg.sender, "Invalid signer");

        usedSyndromes[sessionHash] = true;
        emit SyndromeAccepted(msg.sender, syndrome, sessionHash);
    }

    function validateSyndromeWeight(bytes32 syndrome) public pure returns (bool) {
        uint256 onesCount = 0;
        for (uint256 i = 0; i < 256; i++) {
            if ((uint256(syndrome) >> i) & 1 == 1) {
                onesCount++;
            }
        }
        return onesCount == REQUIRED_SYNDROME_WEIGHT;
    }
}

/// @notice Attack contract trying to inject fake or replayed syndromes
contract SyndromeIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function injectFakeSyndrome(bytes32 forgedSyndrome) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("submitSyndrome(bytes32)", forgedSyndrome)
        );
    }
}
