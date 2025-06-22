// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AirGapProofVerifier — Accepts proofs signed/generated in air-gapped environments
contract AirGapProofVerifier {
    address public expectedSigner;

    event AirGapProofAccepted(address indexed submitter, bytes32 proofHash, uint256 timestamp);

    constructor(address signer) {
        expectedSigner = signer;
    }

    function submitProof(bytes32 proofHash, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encodePacked(proofHash, msg.sender));
        address signer = recoverSigner(digest, signature);
        require(signer == expectedSigner, "Invalid air-gapped signer");
        emit AirGapProofAccepted(msg.sender, proofHash, block.timestamp);
    }

    function recoverSigner(bytes32 hash, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "Invalid signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        return ecrecover(hash, v, r, s);
    }
}
