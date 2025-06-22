// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

interface IConfidentialVerifier {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[] calldata inputs
    ) external view returns (bool);
}

/// @title ConfidentialComputeBridge — Confidential Computing Validator via ZKP + Attestation
contract ConfidentialComputeBridge {
    using ECDSA for bytes32;

    address public trustedAttester;
    IConfidentialVerifier public verifier;

    mapping(bytes32 => bool) public usedNullifiers;

    event ConfidentialResultAccepted(bytes32 indexed resultHash, address indexed sender);
    event ResultRejected(string reason);

    constructor(address _verifier, address _attester) {
        verifier = IConfidentialVerifier(_verifier);
        trustedAttester = _attester;
    }

    modifier onlyWithAttestation(bytes32 hash, bytes calldata sig) {
        require(
            keccak256(abi.encodePacked(msg.sender, hash)).toEthSignedMessageHash().recover(sig) == trustedAttester,
            "Invalid attestation"
        );
        _;
    }

    /// ✅ Submit ZK-verified confidential compute result with attestation + nullifier
    function submitConfidentialResult(
        bytes32 resultHash,
        bytes32 nullifier,
        bytes32 attestationHash,
        bytes calldata sig,
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[] calldata inputs
    ) external onlyWithAttestation(attestationHash, sig) {
        require(!usedNullifiers[nullifier], "Nullifier replay");

        bool ok = verifier.verifyProof(a, b, c, inputs);
        require(ok, "ZKP verification failed");

        usedNullifiers[nullifier] = true;
        emit ConfidentialResultAccepted(resultHash, msg.sender);
    }
}
