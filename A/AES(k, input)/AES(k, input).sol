// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AESCommitmentVerifier — AES(k, input) done offchain; hash committed onchain
contract AESCommitmentVerifier {
    struct AESCommitment {
        address submitter;
        bytes32 aesOutputHash; // keccak256(AES(k, input))
        string label;
        uint256 timestamp;
    }

    AESCommitment[] public commitments;

    event AESCommitted(uint256 indexed id, address indexed user, bytes32 hash);

    function commitAES(bytes32 aesOutputHash, string calldata label) external returns (uint256) {
        commitments.push(AESCommitment(msg.sender, aesOutputHash, label, block.timestamp));
        uint256 id = commitments.length - 1;
        emit AESCommitted(id, msg.sender, aesOutputHash);
        return id;
    }

    function getCommitment(uint256 id) external view returns (AESCommitment memory) {
        return commitments[id];
    }

    function totalCommitments() external view returns (uint256) {
        return commitments.length;
    }
}
