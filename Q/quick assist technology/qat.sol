// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title QuickAssistAttackDefense - Attack and Defense Simulation for Quick Assist Technology in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Quick Assist (Accepts any external "quick verification" without on-chain rechecking)
contract InsecureQuickAssist {
    event ProofAccepted(address indexed user, bytes32 proofHash);

    function submitProof(bytes32 quickAssistResult) external {
        // 🔥 No validation, blindly accept quick assist proof!
        emit ProofAccepted(msg.sender, quickAssistResult);
    }
}

/// @notice Secure Quick Assist Handling with On-Chain Validation
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SecureQuickAssist is Ownable {
    using ECDSA for bytes32;

    address public trustedAssistSigner;
    mapping(bytes32 => bool) public usedProofs;

    event ProofAccepted(address indexed user, bytes32 proofHash);

    constructor(address _trustedAssistSigner) {
        require(_trustedAssistSigner != address(0), "Invalid signer");
        trustedAssistSigner = _trustedAssistSigner;
    }

    function submitSecureProof(
        bytes32 rawProof,
        uint256 nonce,
        bytes calldata signature
    ) external {
        bytes32 proofHash = keccak256(abi.encodePacked(msg.sender, rawProof, nonce, address(this), block.chainid));
        require(!usedProofs[proofHash], "Proof already used");

        address signer = proofHash.toEthSignedMessageHash().recover(signature);
        require(signer == trustedAssistSigner, "Invalid quick assist signature");

        usedProofs[proofHash] = true;
        emit ProofAccepted(msg.sender, rawProof);
    }
}

/// @notice Attack contract trying to inject fake quick assist proofs
contract QuickAssistIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function injectFakeProof(bytes32 forgedProof) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("submitProof(bytes32)", forgedProof)
        );
    }
}
