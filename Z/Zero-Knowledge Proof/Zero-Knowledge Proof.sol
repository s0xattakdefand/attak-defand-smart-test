// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Minimal Groth16-compatible verifier interface (generated externally)
interface IVerifier {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[] calldata publicSignals
    ) external view returns (bool);
}

/// @title ZKProofValidator — ZKP + nullifier replay protection
contract ZKProofValidator {
    IVerifier public verifier;
    mapping(bytes32 => bool) public usedNullifiers;
    address public owner;

    event ProofValidated(address indexed user, bytes32 indexed nullifier);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    constructor(address verifierAddress) {
        verifier = IVerifier(verifierAddress);
        owner = msg.sender;
    }

    /// ✅ Submit ZK proof with public input: [merkleRoot, nullifierHash, signalHash]
    function validateProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[] calldata publicSignals  // [merkleRoot, nullifierHash, signalHash]
    ) external {
        require(publicSignals.length == 3, "Invalid inputs");

        bytes32 nullifier = bytes32(publicSignals[1]);
        require(!usedNullifiers[nullifier], "Nullifier already used");

        bool valid = verifier.verifyProof(a, b, c, publicSignals);
        require(valid, "Invalid ZK proof");

        usedNullifiers[nullifier] = true;
        emit ProofValidated(msg.sender, nullifier);
    }

    /// 🛡️ Optional: Admin function to reset verifier
    function setVerifier(address newVerifier) external onlyOwner {
        verifier = IVerifier(newVerifier);
    }
}
