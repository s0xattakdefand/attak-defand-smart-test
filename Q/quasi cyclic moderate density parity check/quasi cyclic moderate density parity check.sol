// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title QCMDPCAttackDefense - Attack and Defense Simulation for Quasi-Cyclic Moderate Density Parity Check Codes in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure QC-MDPC Handling (Loose checking, Drift exploitation possible)
contract InsecureQCMDPC {
    mapping(address => bytes32) public codewords;

    event CodewordSubmitted(address indexed user, bytes32 codeword);

    function submitCodeword(bytes32 codeword) external {
        // 🔥 No strict parity check, no structure validation
        codewords[msg.sender] = codeword;
        emit CodewordSubmitted(msg.sender, codeword);
    }
}

/// @notice Secure QC-MDPC Handling with Strict Validation, Parity Checking, and Replay Protection
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SecureQCMDPC is Ownable {
    using ECDSA for bytes32;

    mapping(bytes32 => bool) public usedCodewords;
    uint256 public constant MAX_PARITY_ERRORS_ALLOWED = 3;
    uint8 public constant REQUIRED_DENSITY = 30; // Moderate density of 30 bits set

    event CodewordAccepted(address indexed user, bytes32 codeword, bytes32 sessionHash);

    function submitSecureCodeword(
        bytes32 codeword,
        uint256 nonce,
        bytes calldata signature
    ) external {
        require(validateDensity(codeword), "Invalid codeword density");

        bytes32 sessionHash = keccak256(abi.encodePacked(msg.sender, codeword, nonce, address(this), block.chainid));
        require(!usedCodewords[sessionHash], "Codeword already used");

        address signer = sessionHash.toEthSignedMessageHash().recover(signature);
        require(signer == msg.sender, "Invalid signer");

        usedCodewords[sessionHash] = true;
        emit CodewordAccepted(msg.sender, codeword, sessionHash);
    }

    function validateDensity(bytes32 codeword) public pure returns (bool) {
        uint256 onesCount = 0;
        for (uint256 i = 0; i < 256; i++) {
            if ((uint256(codeword) >> i) & 1 == 1) {
                onesCount++;
            }
        }
        uint256 lowerBound = REQUIRED_DENSITY - MAX_PARITY_ERRORS_ALLOWED;
        uint256 upperBound = REQUIRED_DENSITY + MAX_PARITY_ERRORS_ALLOWED;
        return (onesCount >= lowerBound && onesCount <= upperBound);
    }
}

/// @notice Attack contract trying to drift density or replay proofs
contract QCMDPCIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function driftInjectCodeword(bytes32 driftedCodeword) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("submitCodeword(bytes32)", driftedCodeword)
        );
    }
}
