// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title ZKProofOfKnowledge — Verifies that a prover knows the preimage of a known hash without revealing it.
interface IZKVerifier {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[] calldata input  // publicInputs = [hash, nullifierHash]
    ) external view returns (bool);
}

contract ZKProofOfKnowledge {
    IZKVerifier public verifier;
    address public owner;
    mapping(bytes32 => bool) public usedNullifiers;

    event ProofAccepted(address indexed prover, bytes32 indexed nullifier);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    constructor(address verifierAddress) {
        verifier = IZKVerifier(verifierAddress);
        owner = msg.sender;
    }

    /// 🔐 Prove knowledge of preimage x such that hash(x) = knownHash
    /// input[0] = keccak256(x), input[1] = nullifierHash (prevents reuse)
    function proveKnowledge(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[] calldata input
    ) external {
        require(input.length == 2, "Invalid input length");

        bytes32 nullifier = bytes32(input[1]);
        require(!usedNullifiers[nullifier], "Nullifier used");

        bool valid = verifier.verifyProof(a, b, c, input);
        require(valid, "Invalid ZKPoK proof");

        usedNullifiers[nullifier] = true;
        emit ProofAccepted(msg.sender, nullifier);
    }

    /// 🔧 Admin can update the verifier if circuit is upgraded
    function updateVerifier(address newVerifier) external onlyOwner {
        verifier = IZKVerifier(newVerifier);
    }
}
