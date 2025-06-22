// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title QuasiCyclicCodewordAttackDefense - Attack and Defense Simulation for Quasi-Cyclic Codeword Finding in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Quasi-Cyclic Codeword Handling (No structure validation, No binding)
contract InsecureQuasiCyclic {
    mapping(address => bytes32) public submittedCodewords;

    event CodewordSubmitted(address indexed user, bytes32 codeword);

    function submitCodeword(bytes32 codeword) external {
        // 🔥 Accepts any random codeword with no structural validation!
        submittedCodewords[msg.sender] = codeword;
        emit CodewordSubmitted(msg.sender, codeword);
    }
}

/// @notice Secure Quasi-Cyclic Codeword Handling with Validation, Binding, and Replay Protection
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SecureQuasiCyclic is Ownable {
    using ECDSA for bytes32;

    mapping(bytes32 => bool) public usedCodewords;

    uint256 public constant REQUIRED_HAMMING_WEIGHT = 16; // Example structure constraint

    event CodewordValidated(address indexed user, bytes32 codeword, bytes32 sessionHash);

    function validateAndSubmitCodeword(
        bytes32 codeword,
        uint256 nonce,
        bytes calldata signature
    ) external {
        require(validateCodewordStructure(codeword), "Invalid codeword structure");

        bytes32 sessionHash = keccak256(abi.encodePacked(msg.sender, codeword, nonce, address(this), block.chainid));
        require(!usedCodewords[sessionHash], "Codeword already used");

        address signer = sessionHash.toEthSignedMessageHash().recover(signature);
        require(signer == msg.sender, "Invalid signer");

        usedCodewords[sessionHash] = true;
        emit CodewordValidated(msg.sender, codeword, sessionHash);
    }

    function validateCodewordStructure(bytes32 codeword) public pure returns (bool) {
        uint256 weight = 0;
        for (uint256 i = 0; i < 32; i++) {
            uint8 b = uint8(uint256(codeword) >> (i * 8));
            while (b != 0) {
                weight += b & 1;
                b >>= 1;
            }
        }
        return weight == REQUIRED_HAMMING_WEIGHT;
    }
}

/// @notice Attack contract trying to inject or replay invalid quasi-cyclic codewords
contract QuasiCyclicIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function injectFakeCodeword(bytes32 forgedCodeword) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("submitCodeword(bytes32)", forgedCodeword)
        );
    }
}
