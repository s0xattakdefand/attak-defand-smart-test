// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ConfidentialComputeVerifier — ZKP and Attestation Bound Result Verification for Confidential Compute
interface IZKPVerifier {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[] calldata inputs
    ) external view returns (bool);
}

contract ConfidentialComputeVerifier {
    IZKPVerifier public verifier;
    address public trustedAttester;

    mapping(bytes32 => bool) public usedResults;

    event ConfidentialResultAccepted(bytes32 indexed resultHash, address indexed submitter);
    event InvalidResult(bytes32 indexed resultHash, string reason);

    modifier onlyAttester(bytes32 attestationHash, bytes calldata sig) {
        bytes32 msgHash = keccak256(abi.encodePacked(attestationHash, msg.sender)).toEthSignedMessageHash();
        require(msgHash.recover(sig) == trustedAttester, "Invalid attester signature");
        _;
    }

    constructor(address _verifier, address _trustedAttester) {
        verifier = IZKPVerifier(_verifier);
        trustedAttester = _trustedAttester;
    }

    /// ✅ Submit result with zero-knowledge proof and signed attestation
    function submitConfidentialResult(
        bytes32 resultHash,
        bytes32 attestationHash,
        bytes calldata sig,
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[] calldata publicInputs
    ) external onlyAttester(attestationHash, sig) {
        require(!usedResults[resultHash], "Result already used");

        bool isValid = verifier.verifyProof(a, b, c, publicInputs);
        if (!isValid) {
            emit InvalidResult(resultHash, "ZKP verification failed");
            return;
        }

        usedResults[resultHash] = true;
        emit ConfidentialResultAccepted(resultHash, msg.sender);
    }
}
